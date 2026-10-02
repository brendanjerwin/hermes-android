package com.hermes.client.data.auth

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Normalized RFC 8252 native OAuth token set for one gateway. Mirrors the desktop's
 * `NativeTokenSet` (native-oauth.ts): this is the STORED representation, so its field
 * names are camelCase. Gateway `/auth/native/token` + `/auth/native/refresh` responses
 * are snake_case and are parsed separately by [NativeTokenJson.parseTokenResponse] —
 * crossing the two broke the desktop on every restart (#73271).
 */
@Serializable
data class NativeTokenSet(
    val accessToken: String,
    val refreshToken: String,
    /** Absolute unix seconds at which the access token expires; 0 = unknown. */
    val expiresAt: Long,
    val provider: String,
    val userId: String,
)

/**
 * Pure logic for the native-app login mirroring desktop `native-oauth.ts`
 * (app-side half of the gateway's `/auth/native/{authorize,token,refresh}` contract):
 * S256 PKCE generation, authorize-URL building, loopback callback parsing, and
 * token-response normalization. No Android types — everything here is JVM-only and
 * unit-testable.
 */
object NativeAuthLogic {

    /** The gateway status field listing supported auth flows (desktop `NATIVE_FLOW_ID`). */
    const val NATIVE_FLOW_ID = "native_pkce"

    /** The only provider this client forces on `/auth/native/authorize` (the fork's own OIDC plugin). */
    const val SELF_HOSTED_PROVIDER = "self-hosted"

    /** base64url without `=` padding (RFC 7636 §4), the form the gateway's verifier check expects. */
    fun b64url(raw: ByteArray): String =
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw)

    /**
     * PKCE verifier/challenge pair (S256). The verifier is 32 random bytes base64url-encoded
     * (43 chars, within RFC 7636's 43–128 range and the gateway's verifier-length check).
     */
    fun generatePkcePair(random: java.security.SecureRandom = java.security.SecureRandom()): PkcePair {
        val verifierBytes = ByteArray(32)
        random.nextBytes(verifierBytes)
        val verifier = b64url(verifierBytes)
        val challenge = b64url(java.security.MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))
        return PkcePair(verifier, challenge, method = "S256")
    }

    /** High-entropy CSRF `state` value for the loopback round trip. */
    fun generateState(random: java.security.SecureRandom = java.security.SecureRandom()): String {
        val bytes = ByteArray(24)
        random.nextBytes(bytes)
        return b64url(bytes)
    }

    data class PkcePair(val verifier: String, val challenge: String, val method: String)

    /**
     * Build the gateway `/auth/native/authorize` URL the system browser opens.
     * Mirrors desktop `buildNativeAuthorizeUrl`: preserves any base-URL path prefix and
     * URL-encodes every param. [provider] is optional — the Android client always passes
     * `self-hosted` (this fork's OIDC provider), but the parameter stays optional to keep
     * the builder's contract identical to the desktop's.
     */
    fun buildNativeAuthorizeUrl(
        baseUrl: String,
        challenge: String,
        redirectUri: String,
        state: String,
        provider: String? = null,
    ): String {
        val parsed = java.net.URI(baseUrl.trim())
        val prefix = parsed.path?.trimEnd('/') ?: ""
        val q = StringBuilder()
        fun addParam(key: String, value: String) {
            if (q.isNotEmpty()) q.append('&')
            q.append(key).append('=').append(java.net.URLEncoder.encode(value, Charsets.UTF_8))
        }
        addParam("code_challenge", challenge)
        addParam("code_challenge_method", "S256")
        addParam("redirect_uri", redirectUri)
        addParam("state", state)
        if (provider != null) addParam("provider", provider)
        val path = "$prefix/auth/native/authorize"
        // Build the base WITHOUT a query (URI(...) would encode the already-URL-encoded
        // '%' as %25), then append the encoded query raw — same result as the desktop's
        // URLSearchParams + template string.
        val base = java.net.URI(parsed.scheme, parsed.rawUserInfo, parsed.host, parsed.port, path, null, null).toString()
        return "$base?$q"
    }

    /** The `/auth/native/token` endpoint URL for a gateway base URL (mirrors desktop `nativeTokenUrl`). */
    fun nativeTokenUrl(baseUrl: String): String = endpointUrl(baseUrl, "/auth/native/token")

    /** The `/auth/native/refresh` endpoint URL for a gateway base URL (mirrors desktop `nativeRefreshUrl`). */
    fun nativeRefreshUrl(baseUrl: String): String = endpointUrl(baseUrl, "/auth/native/refresh")

    private fun endpointUrl(baseUrl: String, suffix: String): String {
        val parsed = java.net.URI(baseUrl.trim())
        val prefix = parsed.path?.trimEnd('/') ?: ""
        return java.net.URI(parsed.scheme, parsed.rawUserInfo, parsed.host, parsed.port, "$prefix$suffix", null, null).toString()
    }

    /**
     * Parse the loopback redirect the gateway sends the browser to. Returns the `code`,
     * or throws with the gateway's `error` if the flow failed. [expectedState] MUST match
     * (CSRF defense — RFC 6749 §10.12); a mismatch throws rather than proceeding. Mirrors
     * desktop `parseLoopbackCallback`.
     */
    fun parseLoopbackCallback(requestUrl: String, expectedState: String): String {
        // requestUrl is path+query the loopback server received ("/callback?code=…&state=…");
        // resolve against a dummy loopback origin to use java.net.URL's parser.
        val url = if (requestUrl.startsWith("http")) java.net.URI(requestUrl)
        else java.net.URI("http://127.0.0.1$requestUrl")
        val params = url.rawQuery.split('&').filter { it.isNotBlank() }.associate {
            val idx = it.indexOf('=')
            if (idx < 0) it to ""
            else java.net.URLDecoder.decode(it.substring(0, idx), Charsets.UTF_8) to
                java.net.URLDecoder.decode(it.substring(idx + 1), Charsets.UTF_8)
        }
        params["error"]?.takeIf { it.isNotBlank() }?.let { error ->
            val desc = params["error_description"].orEmpty()
            throw NativeLoginException("Gateway rejected native login: $error${desc.takeIf { it.isNotBlank() }?.let { " ($it)" } ?: ""}")
        }
        val code = params["code"].orEmpty()
        if (code.isBlank()) throw NativeLoginException("Loopback callback missing authorization code")
        val state = params["state"].orEmpty()
        if (expectedState.isBlank() || state != expectedState) {
            // Never redeem a code that arrived with a mismatched state — it may be a forged
            // callback trying to inject an attacker's code.
            throw NativeLoginException("Loopback callback state mismatch (possible CSRF)")
        }
        return code
    }

    /**
     * Normalize a `/auth/native/token` (or refresh) JSON response into a [NativeTokenSet],
     * validating the shape. Throws on a missing access token so a malformed response fails
     * loudly rather than storing junk. Mirrors desktop `parseTokenResponse` (snake_case).
     */
    fun parseTokenResponse(body: String, json: Json): NativeTokenSet {
        val obj = runCatching { json.parseToJsonElement(body).jsonObject }
            .getOrElse { throw NativeLoginException("Gateway token response is not a JSON object") }
        val accessToken = obj["access_token"]?.jsonPrimitive?.content.orEmpty()
        if (accessToken.isBlank()) throw NativeLoginException("Gateway token response missing access_token")
        val expiresAt = (obj["expires_at"]?.jsonPrimitive?.content ?: "").toLongOrNull() ?: 0L
        return NativeTokenSet(
            accessToken = accessToken,
            refreshToken = obj["refresh_token"]?.jsonPrimitive?.content.orEmpty(),
            expiresAt = expiresAt,
            provider = obj["provider"]?.jsonPrimitive?.content.orEmpty(),
            userId = obj["user_id"]?.jsonPrimitive?.content.orEmpty(),
        )
    }

    /**
     * Validate a token set loaded from the encrypted local store (camelCase field names,
     * desktop `parseStoredTokenSet`). Store direction only — responses stay snake_case.
     */
    fun parseStoredTokenSet(body: String, json: Json): NativeTokenSet {
        val obj = runCatching { json.parseToJsonElement(body).jsonObject }
            .getOrElse { throw NativeLoginException("Stored token set is not a JSON object") }
        val accessToken = obj["accessToken"]?.jsonPrimitive?.content.orEmpty()
        if (accessToken.isBlank()) throw NativeLoginException("Stored token set missing accessToken")
        val expiresAt = obj["expiresAt"]?.jsonPrimitive?.content?.toLongOrNull() ?: 0L
        return NativeTokenSet(
            accessToken = accessToken,
            refreshToken = obj["refreshToken"]?.jsonPrimitive?.content.orEmpty(),
            expiresAt = expiresAt,
            provider = obj["provider"]?.jsonPrimitive?.content.orEmpty(),
            userId = obj["userId"]?.jsonPrimitive?.content.orEmpty(),
        )
    }

    /**
     * True when a stored token set is at/near expiry and should be refreshed before use.
     * [skewSeconds] refreshes slightly early to avoid a race where the token expires in
     * flight (mirrors the server's 60s cookie floor). Unknown expiry ⇒ refresh.
     */
    fun tokenNeedsRefresh(tokens: NativeTokenSet, nowSeconds: Long, skewSeconds: Long = 60): Boolean =
        tokens.expiresAt <= 0 || nowSeconds >= tokens.expiresAt - skewSeconds
}

/** Failure of any stage of the native (RFC 8252) login round trip. */
class NativeLoginException(message: String, cause: Throwable? = null) :
    com.hermes.client.data.network.HermesApiException(0, message) {
    init {
        cause?.let { initCause(it) }
    }
}