package com.hermes.client.data.auth

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** GatewayConfig mode semantics: OIDC > password > token priority. */
class GatewayConfigOidcModeTest {

    @Test fun isOidc_true_only_with_token_set() {
        assertTrue(GatewayConfig("http://g", oauthTokens = NativeTokenSet("a", "r", 1, "self-hosted", "u")).isOidc)
        assertFalse(GatewayConfig("http://g", token = "loopback-token").isOidc)
        assertFalse(GatewayConfig("http://g", username = "u", password = "p").isOidc)
        assertFalse(GatewayConfig("http://g").isOidc)
    }

    @Test fun priority_oidc_beats_password_and_token_for_the_probe_credential() {
        val c = GatewayConfig(
            "http://g", token = "loop-token", username = "u", password = "p",
            oauthTokens = NativeTokenSet("bearer-at", "r", 1, "self-hosted", "u"),
        )
        assertTrue(c.isOidc)
        assertEquals("bearer-at", c.probeCredential())
    }

    @Test fun probeCredential_without_oidc_uses_session_token() {
        assertEquals("tok", GatewayConfig("http://g", token = "tok").probeCredential())
    }

    @Test fun probeCredential_blank_everything_returns_null() {
        assertNull(GatewayConfig("http://g").probeCredential())
    }

    @Test fun oauthTokens_cleared_sets_isOidc_false() {
        val c = GatewayConfig("http://g", oauthTokens = NativeTokenSet("a", "r", 1, "self-hosted", "u"))
        assertTrue(c.isOidc)
        assertFalse(c.copy(oauthTokens = null).isOidc)
    }

    /** The store direction: camelCase NativeTokenSet round trips through the serializer. */
    @Test fun nativeTokenSet_serializes_camelCase_for_the_store() {
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        val t = NativeTokenSet("at", "rt", 123L, "self-hosted", "u1")
        val encoded = json.encodeToString(NativeTokenSet.serializer(), t)
        assertTrue(encoded.contains("\"accessToken\":\"at\""))
        assertTrue(encoded.contains("\"refreshToken\":\"rt\""))
        assertTrue(encoded.contains("\"expiresAt\":123"))
        val decoded = NativeAuthLogic.parseStoredTokenSet(encoded, json)
        assertEquals(t, decoded)
    }
}

/** Pure-store seam used by NativeTokenClient: round trips through [GatewayConfig]. */
class NativeTokenStoreRoundTripTest {
    @Test fun rotated_set_persists_via_config_copy() {
        val original = GatewayConfig("http://g:9119", token = "", oauthTokens = null)
        val rotated = NativeTokenSet("at2", "rt2", 456, "self-hosted", "u9")
        val updated = original.copy(oauthTokens = rotated)
        assertEquals("http://g:9119", updated.baseUrl)
        assertEquals("at2", updated.oauthTokens?.accessToken)
        assertTrue(updated.isOidc)
        assertFalse(updated.isGated)
    }

    @Test fun cleared_config_keeps_baseUrl_only() {
        val c = GatewayConfig("http://g:9119", oauthTokens = NativeTokenSet("a", "r", 1, "self-hosted", "u"))
        val cleared = c.copy(oauthTokens = null)
        assertEquals("http://g:9119", cleared.baseUrl)
        assertNull(cleared.oauthTokens)
    }
}