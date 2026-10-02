package com.hermes.client.data.auth

data class GatewayConfig(
    val baseUrl: String,
    val token: String = "",
    // Set for a network-exposed (gated) dashboard that requires a password provider. When a
    // username is present the app authenticates via POST /auth/password-login (session cookies)
    // plus a per-socket WS ticket, instead of the loopback session token.
    val username: String = "",
    val password: String = "",
    /**
     * RFC 8252 native OAuth (gateway as authorization server): tokens live in [oauthTokens].
     * Mutually exclusive with the password and token modes — when set, REST authenticates with
     * `Authorization: Bearer <access_token>` and no session-token header or password login is
     * sent. Mode priority when several carry values: OIDC > password > token.
     */
    val oauthTokens: NativeTokenSet? = null,
) {
    /** True when this targets a gated dashboard (basic-auth); false for a loopback/token setup. */
    val isGated: Boolean get() = username.isNotBlank()

    /** True when the stored config holds a native OAuth token set (bearer-authenticated). */
    val isOidc: Boolean get() = oauthTokens != null

    /**
     * The credential to present on an unauthenticated REST/WS setup probe, in the same
     * priority the runtime auth layers resolve: bearer access token in OIDC mode, else the
     * session token. (Password mode probes via a POST login, not a header.)
     */
    fun probeCredential(): String? =
        when {
            isOidc && oauthTokens?.accessToken?.isNotBlank() == true -> oauthTokens.accessToken
            token.isNotBlank() -> token
            else -> null
        }

    /** Base WS endpoint with no auth query — the auth param (?token / ?ticket) is appended later. */
    val wsBase: String
        get() {
            val ws = baseUrl.replaceFirst("https://", "wss://").replaceFirst("http://", "ws://")
            return "${ws.trimEnd('/')}/api/ws"
        }

    /**
     * Loopback WS URL using the session token, e.g. ws://host:9119/api/ws?token=...
     * Only used in non-gated mode; gated mode appends a per-connect ?ticket= instead.
     */
    val wsUrl: String get() = if (token.isBlank()) wsBase else "$wsBase?token=$token"
}

interface CredentialStore {
    fun load(): GatewayConfig?
    fun save(config: GatewayConfig)
    fun clear()
}
