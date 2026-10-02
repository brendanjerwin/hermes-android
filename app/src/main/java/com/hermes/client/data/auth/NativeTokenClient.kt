package com.hermes.client.data.auth

import com.hermes.client.data.network.HermesApiException
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Native OAuth token refresh client, mirroring desktop `native-access-token.ts` +
 * `native-auth-decisions.ts`: `/auth/native/refresh` rotates the token set; single-flight
 * per baseUrl (concurrent callers share one flight instead of racing rotations and losing
 * the winner); a structured 401 on refresh is terminal — tokens are cleared and the caller
 * surfaces a fresh login; a 503/transient keeps them.
 *
 * The gateway never rotates the native access token server-side — the native flow is told
 * to call `/auth/native/refresh` itself (dashboard_auth/middleware.py), so a 401 on a
 * bearer the app still considers unexpired is ambiguous until the refresh has had its say:
 * a live refresh token yields a fresh bearer, a dead one confirms the session is gone
 * (desktop #95701). A 403 is a policy refusal that a rotated token cannot change.
 */
class NativeTokenClient(
    private val json: Json,
    private val store: CredentialStore,
    /** Injectable token-rotation call, so unit tests can drive refresh with MockWebServer. */
    private val refreshTokenSet: suspend (baseUrl: String, tokens: NativeTokenSet) -> NativeTokenSet,
    /** Injectable clock (unix seconds) for expiry math. */
    private val nowSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private val flights = ConcurrentHashMap<String, Deferred<NativeTokenSet?>>()

    /** Result of the authenticator's 401 handling (desktop `resolveOauthRestAuth` semantics). */
    sealed interface RefreshOutcome {
        /** Fresh bearer to retry the original request with. */
        data class Refreshed(val accessToken: String) : RefreshOutcome

        /** Stored config is NOT in OIDC mode — the caller should use its cookie/password path. */
        data object NotOidcMode : RefreshOutcome

        /** Terminal: the refresh token is dead, tokens were cleared — surface a fresh login. */
        data object Terminal : RefreshOutcome
    }

    /**
     * Return a valid access token for the stored gateway config, refreshing via
     * `/auth/native/refresh` if the stored one is at/near expiry. Returns null when there
     * are no tokens or the refresh is terminally rejected (caller re-logins).
     */
    suspend fun ensureAccessToken(): String? {
        val config = store.load() ?: return null
        val tokens = config.oauthTokens ?: return null
        if (!NativeAuthLogic.tokenNeedsRefresh(tokens, nowSeconds())) return tokens.accessToken
        return ensure(config.baseUrl, tokens)?.accessToken?.takeIf { it.isNotBlank() }
    }

    /**
     * Force a refresh of [tokens]: single-flight per baseUrl, terminal on structured 401.
     * `null` when the set is gone. [rejectedAccessToken] implements the desktop's
     * `ensureNativeAccessToken(forceRefresh + rejectedAccessToken)` semantics from a 401
     * handler: a late 401 must reuse a concurrent rotation rather than rotate its winner
     * again, unless the rejecting request carried an OLDER token than the current one.
     */
    suspend fun ensure(baseUrl: String, tokens: NativeTokenSet, rejectedAccessToken: String? = null): NativeTokenSet? {
        val flightKey = baseUrl.trimEnd('/')
        val existing = flights[flightKey]
        if (existing != null && (rejectedAccessToken == null || rejectedAccessToken == tokens.accessToken)) {
            return existing.await()
        }
        if (tokens.refreshToken.isBlank()) {
            // Drop the stored set BEFORE the single-flight bookkeeping: there is no rotation
            // to coordinate, and the caller must see "no tokens" immediately.
            clearTokens(baseUrl)
            return null
        }
        val flight = CoroutineScope(Dispatchers.IO).async {
            rotate(baseUrl, tokens)
        }
        val prior = flights.putIfAbsent(flightKey, flight)
        if (prior != null) {
            flight.cancel()
            return prior.await()
        }
        try {
            return flight.await()
        } finally {
            if (flights[flightKey] === flight) flights.remove(flightKey, flight)
        }
    }

    /**
     * The OkHttp `Authenticator` entry point. Only rotates when the stored config is in
     * OIDC mode; [RefreshOutcome.NotOidcMode] lets the caller (authenticator) fall back to
     * its cookie/password path — an OAuth gateway is "signed in" on the native bearer or a
     * live cookie session, and each mode re-authenticates its own way (desktop:
     * `oauthSessionIsLive` / `resolveOauthRestAuth`).
     */
    suspend fun refreshAfter401(rejectedAccessToken: String?): RefreshOutcome {
        val config = store.load() ?: return RefreshOutcome.NotOidcMode
        val tokens = config.oauthTokens ?: return RefreshOutcome.NotOidcMode
        val rotated = ensure(config.baseUrl, tokens, rejectedAccessToken)
        return rotated?.accessToken?.takeIf { it.isNotBlank() }
            ?.let { RefreshOutcome.Refreshed(it) }
            ?: RefreshOutcome.Terminal
    }

    /** Run one rotation and persist/clear per the 401-terminal rule. Runs inside the single-flight. */
    private suspend fun rotate(baseUrl: String, tokens: NativeTokenSet): NativeTokenSet? {
        return try {
            val rotated = refreshTokenSet(baseUrl, tokens)
            persistTokens(baseUrl, rotated)
            rotated
        } catch (e: HermesApiException) {
            if (e.code == 401) {
                // 401 on refresh means the RT is dead — tokens are dropped so the UI prompts
                // a fresh native login (desktop: #95701). A 503/transient keeps them.
                clearTokens(baseUrl)
                null
            } else {
                throw e
            }
        }
    }

    /** Persist a full rotated set into the stored GatewayConfig. */
    private suspend fun persistTokens(baseUrl: String, rotated: NativeTokenSet) {
        val config = store.load() ?: return
        if (config.baseUrl.trimEnd('/') != baseUrl.trimEnd('/')) return
        store.save(config.copy(oauthTokens = rotated))
    }

    /** Drop the stored token set (config itself remains — baseUrl is still needed to re-login). */
    suspend fun clearTokens(baseUrl: String) {
        val config = store.load() ?: return
        if (config.baseUrl.trimEnd('/') != baseUrl.trimEnd('/')) return
        store.save(config.copy(oauthTokens = null))
    }

    /**
     * POST /api/auth/ws-ticket authenticated with the CURRENT stored bearer — the
     * ws-ticket endpoint is auth-required and the cookieless native session has no
     * cookies to fall back on. Returns the 30s single-use ticket or null.
     */
    fun ticketWithBearer(client: OkHttpClient): String? {
        val config = store.load() ?: return null
        val tokens = config.oauthTokens ?: return null
        return runCatching {
            client.newCall(
                Request.Builder()
                    .url("${config.baseUrl.trimEnd('/')}/api/auth/ws-ticket")
                    .header("Authorization", "Bearer ${tokens.accessToken}")
                    .post(ByteArray(0).toRequestBody(null))
                    .build(),
            ).execute().use { resp ->
                if (!resp.isSuccessful) return@use null
                json.parseToJsonElement(resp.body?.string().orEmpty()).jsonObject["ticket"]
                    ?.jsonPrimitive?.content
            }
        }.getOrNull()
    }

    /** One `/auth/native/refresh` POST (JSON body, cookieless), 15s timeout, parsed snake_case. */
    companion object {
        private val JSON_MEDIA = "application/json".toMediaType()

        /**
         * Default rotation call used in production: POST the current refresh_token + provider
         * to the gateway and parse the rotated set. The body is the OBJECT, not a pre-stringified
         * string — pre-stringifying double-encodes it and the gateway's Pydantic model rejects
         * it with 422 "Input should be a valid dictionary" (desktop `resolveJsonBody`).
         */
        fun defaultRefreshCall(json: Json): suspend (String, NativeTokenSet) -> NativeTokenSet {
            return { baseUrl, tokens ->
                val url = NativeAuthLogic.nativeRefreshUrl(baseUrl)
                val body = json.encodeToString(
                    buildJsonObject {
                        put("refresh_token", tokens.refreshToken)
                        put("provider", tokens.provider)
                    },
                )
                val client = OkHttpClient.Builder()
                    .callTimeout(15_000, java.util.concurrent.TimeUnit.MILLISECONDS)
                    .build()
                client.newCall(
                    Request.Builder().url(url)
                        .post(body.toRequestBody("application/json".toMediaType()))
                        .build(),
                ).execute().use { resp ->
                    val respBody = resp.body?.string().orEmpty()
                    if (!resp.isSuccessful) {
                        throw HermesApiException(resp.code, "refresh failed: ${respBody.take(180)}")
                    }
                    NativeAuthLogic.parseTokenResponse(respBody, json)
                }
            }
        }
    }
}