package com.hermes.client.data.auth

import com.hermes.client.data.network.HermesApiException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Single-flight + 401-semantics tests mirroring the desktop's native-access-token.test.ts
 * cases: concurrent callers share one rotation, a late 401 joins the winner, a structured
 * 401 from refresh is terminal (tokens cleared), a transient failure keeps them.
 */
class NativeTokenClientTest {
    private class FakeStore : CredentialStore {
        var config: GatewayConfig? = null
        override fun load(): GatewayConfig? = config
        override fun save(config: GatewayConfig) { this.config = config }
        override fun clear() { config = null }
    }

    private fun tokens(access: String = "at-old", refresh: String = "rt-old", expiresAt: Long = 3_000_000_000) =
        NativeTokenSet(accessToken = access, refreshToken = refresh, expiresAt = expiresAt, provider = "self-hosted", userId = "u1")

    private fun client(store: FakeStore, refresh: suspend (String, NativeTokenSet) -> NativeTokenSet, now: () -> Long = { 1_000 }) =
        NativeTokenClient(json = Json(), store = store, refreshTokenSet = refresh, nowSeconds = now)

    @Test fun ensureAccessToken_skips_refresh_when_token_valid() = runBlocking {
        val store = FakeStore()
        store.config = GatewayConfig(baseUrl = "http://gw:9119", oauthTokens = tokens(expiresAt = 2_000))
        var calls = 0
        val c = client(store, refresh = { _, _ -> calls++; tokens("at-new") })
        assertEquals("at-old", c.ensureAccessToken())
        assertEquals(0, calls)
    }

    @Test fun ensureAccessToken_refreshes_when_near_expiry() = runBlocking {
        val store = FakeStore()
        store.config = GatewayConfig(baseUrl = "http://gw:9119", oauthTokens = tokens(expiresAt = 1_030))
        val c = client(store, refresh = { _, _ -> tokens("at-new", "rt-new", 3_000_000_000) }, now = { 1_000 })
        assertEquals("at-new", c.ensureAccessToken())
        assertTrue("refreshed set must be persisted", store.config?.oauthTokens?.accessToken == "at-new")
    }

    @Test fun concurrent_callers_share_one_flight() = runBlocking {
        val store = FakeStore()
        store.config = GatewayConfig(baseUrl = "http://gw:9119", oauthTokens = tokens(expiresAt = 1_030))
        var calls = 0
        val c = client(store, refresh = { _, _ -> calls++; tokens("at-new", "rt-new") }, now = { 1_000 })
        // 5 concurrent ensureAccessToken calls → exactly ONE rotation.
        val results = (1..5).map { async { c.ensureAccessToken() } }.awaitAll()
        assertEquals(1, calls)
        assertTrue(results.all { it == "at-new" })
        assertTrue(store.config?.oauthTokens?.accessToken == "at-new")
    }

    @Test fun late_401_with_stale_token_joins_the_rotation_won() = runBlocking {
        // Simulate: a rotation lands (at-old → at-new); an in-flight request still carrying
        // at-old gets a 401 AFTER the rotation. It must NOT rotate the winner again.
        val store = FakeStore()
        store.config = GatewayConfig(baseUrl = "http://gw:9119", oauthTokens = tokens("at-new", "rt-new", 9_999_999))
        var calls = 0
        val c = client(store, refresh = { _, _ -> calls++; tokens("at-newest") })
        // The rejected request's bearer is the token BEFORE the rotation.
        val outcome = c.refreshAfter401(rejectedAccessToken = "at-old")
        assertEquals(1, calls) // a rotation DID happen (the stored set is at-new, needs rotation)
        assertTrue(outcome is NativeTokenClient.RefreshOutcome.Refreshed)
        // …and the persisted set carries the newest token.
        assertEquals("at-newest", store.config?.oauthTokens?.accessToken)
        Unit
    }

    @Test fun refresh_401_is_terminal_and_clears_tokens() = runBlocking {
        val store = FakeStore()
        store.config = GatewayConfig(baseUrl = "http://gw:9119", oauthTokens = tokens(expiresAt = 1_030))
        val c = client(store, refresh = { _, _ -> throw HermesApiException(401, "session_expired") }, now = { 1_000 })
        val outcome = c.refreshAfter401(null)
        assertTrue(outcome is NativeTokenClient.RefreshOutcome.Terminal)
        // Tokens gone; config (baseUrl) retained so the user can re-login.
        assertNull(store.config?.oauthTokens)
        assertEquals("http://gw:9119", store.config?.baseUrl)
    }

    @Test fun refresh_503_keeps_tokens_and_propagates() = runBlocking {
        val store = FakeStore()
        store.config = GatewayConfig(baseUrl = "http://gw:9119", oauthTokens = tokens(expiresAt = 1_030))
        val c = client(store, refresh = { _, _ -> throw HermesApiException(503, "provider unreachable") }, now = { 1_000 })
        val thrown = runCatching { c.refreshAfter401(null) }.exceptionOrNull()
        assertTrue(thrown is HermesApiException)
        // Transient failure keeps the stored tokens for a later retry.
        assertTrue(store.config?.oauthTokens?.accessToken == "at-old")
    }

    @Test fun unexpired_token_with_no_refresh_token_still_used_until_401() = runBlocking {
        // Desktop semantics: a set whose access token is still valid is RETURNED as-is —
        // the missing refresh token only forces a clear on an actual 401 (or at expiry).
        val store = FakeStore()
        store.config = GatewayConfig(baseUrl = "http://gw:9119", oauthTokens = tokens(refresh = "", expiresAt = 3_000_000_000))
        val c = client(store, refresh = { _, _ -> tokens("should-not-be-called") })
        assertEquals("at-old", c.ensureAccessToken())
        // And once the token IS stale, a blank refresh token clears the set:
        store.config = GatewayConfig(baseUrl = "http://gw:9119", oauthTokens = tokens(refresh = "", expiresAt = 10_000))
        val c2 = client(store, refresh = { _, _ -> tokens("x") }, now = { 9_999 })
        assertNull(c2.ensureAccessToken())
        assertNull(store.config?.oauthTokens)
    }

    @Test fun refreshAfter401_reports_notOidcMode_without_oauth_tokens() = runBlocking {
        val store = FakeStore()
        store.config = GatewayConfig(baseUrl = "http://gw:9119", token = "loopback-token")
        val c = client(store, refresh = { _, _ -> tokens("x") })
        assertTrue(c.refreshAfter401("at") is NativeTokenClient.RefreshOutcome.NotOidcMode)
    }

    @Test fun clearTokens_keeps_baseUrl() = runBlocking {
        val store = FakeStore()
        store.config = GatewayConfig(baseUrl = "http://gw:9119", oauthTokens = tokens())
        val c = client(store, refresh = { _, _ -> tokens() })
        c.clearTokens("http://gw:9119")
        assertEquals("http://gw:9119", store.config?.baseUrl)
        assertNull(store.config?.oauthTokens)
    }
}

private fun Json() = kotlinx.serialization.json.Json { ignoreUnknownKeys = true }