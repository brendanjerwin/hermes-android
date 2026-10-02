package com.hermes.client.data.network

import com.hermes.client.data.auth.GatewayConfig
import com.hermes.client.data.diagnostics.DebugLog
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.Authenticator
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.Route
import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory cookie store for the gated dashboard's session cookies
 * (`hermes_session_at` / `hermes_session_rt`). The dashboard rotates the access cookie on
 * refresh by sending a new Set-Cookie, so we key by name and overwrite — the jar then carries
 * whatever the server most recently issued. Cleared on logout / config change; a fresh login
 * after an app restart repopulates it.
 */
class InMemoryCookieJar : CookieJar {
    private val byHost = ConcurrentHashMap<String, ConcurrentHashMap<String, Cookie>>()

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        val jar = byHost.getOrPut(url.host) { ConcurrentHashMap() }
        for (c in cookies) jar[c.name] = c
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        val jar = byHost[url.host] ?: return emptyList()
        val now = System.currentTimeMillis()
        // matches() enforces path/secure/domain rules; expiry guards rotated-out cookies.
        return jar.values.filter { it.matches(url) && it.expiresAt > now }
    }

    fun clear() = byHost.clear()
}

/**
 * Authenticates against a gated (basic-auth) Hermes dashboard: POST /auth/password-login to mint
 * session cookies, and POST /api/auth/ws-ticket for a single-use WebSocket ticket. REST requests
 * then authenticate transparently via [cookieJar] on the shared OkHttp client.
 */
class GatedAuth(
    private val json: Json,
    private val configProvider: () -> GatewayConfig?,
) {
    val cookieJar = InMemoryCookieJar()

    // A bare client (NO authenticator → no re-auth recursion) that shares the cookie jar so the
    // login response's Set-Cookie lands where authenticated requests will read it.
    private val loginClient by lazy { OkHttpClient.Builder().cookieJar(cookieJar).build() }

    /** Log in with the stored username/password; session cookies land in [cookieJar]. */
    fun login(): Boolean {
        val cfg = configProvider() ?: return false
        if (cfg.username.isBlank()) return false
        val payload: JsonObject = buildJsonObject {
            put("provider", "basic")
            put("username", cfg.username)
            put("password", cfg.password)
        }
        val ok = runCatching {
            val req = Request.Builder()
                .url("${cfg.baseUrl.trimEnd('/')}/auth/password-login")
                .post(json.encodeToString(JsonObject.serializer(), payload).toRequestBody(JSON_MEDIA))
                .build()
            loginClient.newCall(req).execute().use { it.isSuccessful }
        }.getOrDefault(false)
        DebugLog.log("ws", "gated login -> $ok")
        return ok
    }

    /**
     * Mint a single-use (30s) WS ticket. [client] must carry the cookie jar + authenticator so a
     * missing session is recovered (401 → login → retry) before the ticket is issued.
     */
    fun wsTicket(client: OkHttpClient): String? {
        val cfg = configProvider() ?: return null
        val req = Request.Builder()
            .url("${cfg.baseUrl.trimEnd('/')}/api/auth/ws-ticket")
            .post(ByteArray(0).toRequestBody(null))
            .build()
        return runCatching {
            client.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return null
                val body = resp.body?.string().orEmpty()
                json.parseToJsonElement(body).jsonObject["ticket"]?.jsonPrimitive?.content
            }
        }.getOrNull()
    }

    /**
     * One-off login probe with explicit values for the setup "Test" button — uses a throwaway
     * client so it neither persists creds nor disturbs the live session cookies.
     */
    fun probeLogin(baseUrl: String, username: String, password: String): Boolean {
        val payload: JsonObject = buildJsonObject {
            put("provider", "basic")
            put("username", username)
            put("password", password)
        }
        return runCatching {
            val req = Request.Builder()
                .url("${baseUrl.trimEnd('/')}/auth/password-login")
                .post(json.encodeToString(JsonObject.serializer(), payload).toRequestBody(JSON_MEDIA))
                .build()
            OkHttpClient().newCall(req).execute().use { it.isSuccessful }
        }.getOrDefault(false)
    }

    private companion object {
        val JSON_MEDIA = "application/json".toMediaType()
    }
}

/**
 * On a 401 from the gateway, re-authenticate and retry the request ONCE. Two mechanisms:
 *
 *  - OIDC mode (RFC 8252 native flow): single-flight refresh via [NativeTokenClient], then
 *    retry with the freshly rotated bearer. A terminal refresh (401 from
 *    /auth/native/refresh, i.e. a dead RT) clears the tokens and the authenticator gives
 *    up so the caller surfaces a fresh login (desktop `shouldRotateNativeTokenAfterRejection`:
 *    only a structured 401 qualifies; a 403 is a policy refusal for an identity the gate
 *    DID recognize, and a rotated token cannot change it).
 *  - Password mode: log in once (cookies land in the jar) and retry.
 *
 * A marker header prevents an infinite re-auth loop if the retry still fails (e.g. wrong
 * password / dead RT).
 */
class GatedAuthenticator(
    private val auth: GatedAuth,
    private val tokenClient: com.hermes.client.data.auth.NativeTokenClient? = null,
) : Authenticator {
    override fun authenticate(route: Route?, response: Response): Request? {
        if (response.request.header(RETRY_MARKER) != null) return null
        // Rebuild with the marker FIRST so any branch that returns non-null is already fenced
        // against an infinite re-auth loop.
        val original = response.request.newBuilder().header(RETRY_MARKER, "1").build()
        // No native-token client wired → pure password mode (loopback/cookie jar).
        if (tokenClient == null) {
            return if (auth.login()) original else null
        }
        val outcome = kotlinx.coroutines.runBlocking {
            runCatching { tokenClient.refreshAfter401(rejectedAccessTokenOf(response)) }.getOrNull()
        }
        return when (outcome) {
            is com.hermes.client.data.auth.NativeTokenClient.RefreshOutcome.Refreshed ->
                original.newBuilder().header("Authorization", "Bearer ${outcome.accessToken}").build()
            is com.hermes.client.data.auth.NativeTokenClient.RefreshOutcome.NotOidcMode -> {
                // Stored config is password/token mode: log in once (cookies land in the jar,
                // re-applied on the retried request).
                if (auth.login()) original else null
            }
            // Terminal (dead RT) or error → give up; the caller surfaces a fresh login.
            else -> null
        }
    }

    /** The access token the rejected request carried (null/plain when none). */
    private fun rejectedAccessTokenOf(response: Response): String? =
        response.request.header("Authorization")
            ?.takeIf { it.startsWith("Bearer ") }
            ?.removePrefix("Bearer ")
            ?.takeIf { it.isNotBlank() }

    private companion object {
        const val RETRY_MARKER = "X-Hermes-Reauth"
    }
}
