package com.hermes.client.data.auth

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mirrors the desktop's native-oauth.test.ts cases for the pure helpers. */
class NativeAuthLogicTest {
    private val json = Json { ignoreUnknownKeys = true }

    // --- PKCE generation -------------------------------------------------------

    @Test fun generatePkcePair_produces_verifier_in_RFC_length_and_S256_challenge() {
        val pair = NativeAuthLogic.generatePkcePair()
        assertEquals(43, pair.verifier.length) // 32 bytes b64url
        assertTrue("verifier must be in RFC 7636's 43–128 range", pair.verifier.length in 43..128)
        assertFalse("challenge must be unpadded base64url", pair.challenge.contains('='))
        assertFalse("verifier must be unpadded base64url", pair.verifier.contains('='))
        assertFalse("challenge must not use standard base64 chars", pair.challenge.contains('+') || pair.challenge.contains('/'))
        // S256: challenge == BASE64URL-UNPADDED(SHA256(US-ASCII(verifier)))
        val expected = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(pair.verifier.toByteArray(Charsets.US_ASCII)))
        assertEquals(expected, pair.challenge)
        assertEquals("S256", pair.method)
    }

    @Test fun generateState_is_32_char_unpadded_urlsafe() {
        val state = NativeAuthLogic.generateState()
        assertEquals(32, state.length) // 24 bytes b64url
        assertFalse(state.contains('=') || state.contains('+') || state.contains('/'))
    }

    // --- authorize URL builder --------------------------------------------------

    @Test fun buildNativeAuthorizeUrl_encodes_params_forces_provider_and_preserves_prefix() {
        val url = NativeAuthLogic.buildNativeAuthorizeUrl(
            baseUrl = "https://gw.example.com",
            challenge = "CHAL",
            redirectUri = "http://127.0.0.1:51000/callback",
            state = "STATE",
            provider = NativeAuthLogic.SELF_HOSTED_PROVIDER,
        )
        assertEquals(
            "https://gw.example.com/auth/native/authorize" +
                "?code_challenge=CHAL&code_challenge_method=S256" +
                "&redirect_uri=http%3A%2F%2F127.0.0.1%3A51000%2Fcallback&state=STATE" +
                "&provider=self-hosted",
            url,
        )
    }

    @Test fun buildNativeAuthorizeUrl_omits_provider_when_null_and_keeps_path_prefix() {
        val url = NativeAuthLogic.buildNativeAuthorizeUrl(
            baseUrl = "https://gw.example.com/hermes",
            challenge = "C",
            redirectUri = "http://127.0.0.1:1/cb",
            state = "S",
        )
        assertEquals(
            "https://gw.example.com/hermes/auth/native/authorize" +
                "?code_challenge=C&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A1%2Fcb&state=S",
            url,
        )
    }

    /** The app's own forced-provider shape as the Setup screen drives it. */
    @Test fun buildNativeAuthorizeUrl_always_carries_provider_self_hosted_in_app_flow() {
        val url = NativeAuthLogic.buildNativeAuthorizeUrl(
            baseUrl = "http://10.0.0.2:9119/",
            challenge = "c",
            redirectUri = "http://127.0.0.1:49152/callback",
            state = "s",
            provider = NativeAuthLogic.SELF_HOSTED_PROVIDER,
        )
        assertTrue(url.contains("&provider=self-hosted"))
        assertTrue(url.contains("code_challenge_method=S256"))
        assertTrue(url.startsWith("http://10.0.0.2:9119/auth/native/authorize"))
    }

    // --- loopback callback parsing ----------------------------------------------

    @Test fun parseLoopbackCallback_returns_code_on_state_match() {
        assertEquals("abc123", NativeAuthLogic.parseLoopbackCallback("/callback?code=abc123&state=xyz", "xyz"))
    }

    @Test fun parseLoopbackCallback_full_url_form_also_accepted() {
        assertEquals(
            "abc",
            NativeAuthLogic.parseLoopbackCallback("http://127.0.0.1:51000/callback?code=abc&state=s", "s"),
        )
    }

    @Test fun parseLoopbackCallback_throws_on_state_mismatch() {
        val thrown = runCatching {
            NativeAuthLogic.parseLoopbackCallback("/callback?code=abc&state=attacker", "expected")
        }.exceptionOrNull()
        assertTrue("must throw", thrown is NativeLoginException)
        assertTrue(thrown!!.message!!.contains("state mismatch", ignoreCase = true))
    }

    @Test fun parseLoopbackCallback_surfaces_gateway_error_param() {
        val thrown = runCatching {
            NativeAuthLogic.parseLoopbackCallback("/callback?error=access_denied&error_description=nope", "xyz")
        }.exceptionOrNull()
        assertTrue(thrown is NativeLoginException)
        assertTrue(thrown!!.message!!.contains("access_denied"))
        assertTrue(thrown.message!!.contains("nope"))
    }

    @Test fun parseLoopbackCallback_throws_when_code_absent() {
        val thrown = runCatching {
            NativeAuthLogic.parseLoopbackCallback("/callback?state=xyz", "xyz")
        }.exceptionOrNull()
        assertTrue(thrown is NativeLoginException)
        assertTrue(thrown!!.message!!.contains("missing authorization code", ignoreCase = true))
    }

    // --- endpoint URL builders ----------------------------------------------------

    @Test fun nativeTokenUrl_and_refreshUrl_strip_trailing_slash_and_keep_path() {
        assertEquals("https://gw.example.com/auth/native/token", NativeAuthLogic.nativeTokenUrl("https://gw.example.com/"))
        assertEquals("https://gw.example.com/auth/native/refresh", NativeAuthLogic.nativeRefreshUrl("https://gw.example.com"))
        assertEquals(
            "https://gw.example.com/prefix/auth/native/token",
            NativeAuthLogic.nativeTokenUrl("https://gw.example.com/prefix"),
        )
    }

    // --- token response normalization (snake_case from the gateway) ---------------

    @Test fun parseTokenResponse_full_body_maps_snake_case() {
        val t = NativeAuthLogic.parseTokenResponse(
            """{"access_token":"at1","refresh_token":"rt1","token_type":"Bearer",
                "expires_at":1750000000,"provider":"self-hosted","user_id":"u-stored"}""",
            json,
        )
        assertEquals("at1", t.accessToken)
        assertEquals("rt1", t.refreshToken)
        assertEquals(1750000000L, t.expiresAt)
        assertEquals("self-hosted", t.provider)
        assertEquals("u-stored", t.userId)
    }

    @Test fun parseTokenResponse_missing_access_token_fails_loudly() {
        val thrown = runCatching {
            NativeAuthLogic.parseTokenResponse("""{"refresh_token":"rt"}""", json)
        }.exceptionOrNull()
        assertTrue(thrown is NativeLoginException)
        assertTrue(thrown!!.message!!.contains("missing access_token"))
    }

    @Test fun parseTokenResponse_tolerates_missing_optional_fields() {
        val t = NativeAuthLogic.parseTokenResponse("""{"access_token":"at"}""", json)
        assertEquals("", t.refreshToken)
        assertEquals(0L, t.expiresAt)
        assertEquals("", t.provider)
        assertEquals("", t.userId)
    }

    // --- stored token set (camelCase; directions must never cross — desktop #73271) ---

    @Test fun parseStoredTokenSet_reads_camelCase_shape() {
        val t = NativeAuthLogic.parseStoredTokenSet(
            """{"accessToken":"at-stored","refreshToken":"rt-stored","expiresAt":1893456000,
                "provider":"self-hosted","userId":"u-stored"}""",
            json,
        )
        assertEquals("at-stored", t.accessToken)
        assertEquals("rt-stored", t.refreshToken)
        assertEquals(1893456000L, t.expiresAt)
        assertEquals("self-hosted", t.provider)
        assertEquals("u-stored", t.userId)
    }

    @Test fun parseStoredTokenSet_rejects_snake_case_gateway_response() {
        val thrown = runCatching {
            // A gateway response pasted into the store slot must fail loudly, not half-load.
            NativeAuthLogic.parseStoredTokenSet("""{"access_token":"at","user_id":"u"}""", json)
        }.exceptionOrNull()
        assertTrue(thrown is NativeLoginException)
    }

    // --- expiry / refresh-need check ---------------------------------------------

    @Test fun tokenNeedsRefresh_unknown_or_zero_expiry_needs_refresh() {
        val t = NativeTokenSet(accessToken = "a", refreshToken = "r", expiresAt = 0, provider = "", userId = "")
        assertTrue(NativeAuthLogic.tokenNeedsRefresh(t, nowSeconds = 1000))
    }

    @Test fun tokenNeedsRefresh_within_skew_refreshes_early() {
        val t = NativeTokenSet("a", "r", expiresAt = 1000 + 30, provider = "", userId = "")
        // 30s left, 60s skew ⇒ refresh now.
        assertTrue(NativeAuthLogic.tokenNeedsRefresh(t, nowSeconds = 1000))
    }

    @Test fun tokenNeedsRefresh_far_from_expiry_keeps_token() {
        val t = NativeTokenSet("a", "r", expiresAt = 1000 + 301, provider = "", userId = "")
        assertFalse(NativeAuthLogic.tokenNeedsRefresh(t, nowSeconds = 1000))
    }
}