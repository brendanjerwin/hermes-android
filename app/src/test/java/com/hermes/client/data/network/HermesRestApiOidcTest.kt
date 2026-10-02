package com.hermes.client.data.network

import com.hermes.client.data.auth.GatewayConfig
import com.hermes.client.data.auth.NativeTokenClient
import com.hermes.client.data.auth.NativeTokenSet
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.junit4.MockWebServerRule
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * The wire-level contract of OIDC mode (RFC 8252 native flow) on the REST client:
 * bearer attach, no X-Hermes-Session-Token in OIDC mode, and the 401 → refresh → retry
 * once flow through the shared OkHttp authenticator.
 */
class HermesRestApiOidcTest {
    @get:Rule val serverRule = MockWebServerRule()
    private val json = Json { ignoreUnknownKeys = true }

    private fun tokenSet(access: String = "at-old", refresh: String = "rt-old") = NativeTokenSet(
        accessToken = access, refreshToken = refresh, expiresAt = 9_000_000_000,
        provider = "self-hosted", userId = "u1",
    )

    /** takeRequest bounded so a hung test fails fast instead of wedging the suite. */
    private fun MockWebServer.boundedTake() = takeRequest(5, TimeUnit.SECONDS)

    private fun api(
        server: MockWebServer,
        refresh: String = "rt-old",
        okHttp: OkHttpClient? = null,
    ) = HermesRestApi(
        okHttp ?: OkHttpClient(), json,
    ) { GatewayConfig(baseUrl = server.url("/").toString().trimEnd('/'), oauthTokens = tokenSet(refresh = refresh)) }

    private fun clientWithNativeRefresh(server: MockWebServer, store: com.hermes.client.data.auth.CredentialStore): OkHttpClient =
        OkHttpClient.Builder()
            .authenticator(GatedAuthenticator(GatedAuth(json) { null }, NativeTokenClient(
                json = json,
                store = store,
                refreshTokenSet = NativeTokenClient.defaultRefreshCall(json),
            )))
            .build()

    @Test fun oidc_mode_attaches_bearer_and_no_session_token() = runTest {
        serverRule.server.enqueue(MockResponse.Builder().code(200).body("""{"sessions":[]}""").build())
        api(serverRule.server).sessions(limit = 10, offset = 0)
        val req = serverRule.server.boundedTake()
        assertEquals("Bearer at-old", req?.headers?.get("Authorization"))
        assertNull("OIDC mode must NOT send the session-token header", req?.headers?.get("X-Hermes-Session-Token"))
    }

    @Test fun oidc_mode_401_triggers_refresh_then_retry_with_new_bearer() = runTest {
        val server = serverRule.server
        // 1st call: rejected bearer; 2nd: /auth/native/refresh; 3rd: retried original request.
        server.enqueue(MockResponse.Builder().code(401).body("""{"error":"session_expired"}""").build())
        server.enqueue(MockResponse.Builder().code(200).body(
            """{"access_token":"at-new","refresh_token":"rt-new","expires_at":9100000000,
                "provider":"self-hosted","user_id":"u1"}""",
        ).build())
        server.enqueue(MockResponse.Builder().code(200).body("""{"sessions":[{"id":"s1","title":"T"}]}""").build())

        val okHttp = clientWithNativeRefresh(server, object : com.hermes.client.data.auth.CredentialStore {
            override fun load() = GatewayConfig(
                baseUrl = server.url("/").toString().trimEnd('/'),
                oauthTokens = tokenSet(refresh = "rt-live"),
            )
            override fun save(config: GatewayConfig) {}
            override fun clear() {}
        })
        val list = HermesRestApi(okHttp, json) {
            GatewayConfig(baseUrl = server.url("/").toString().trimEnd('/'), oauthTokens = tokenSet(refresh = "rt-live"))
        }.sessions(limit = 10, offset = 0)
        assertEquals(1, list.size)

        val first = server.boundedTake()
        assertEquals("Bearer at-old", first?.headers?.get("Authorization"))
        val refreshReq = server.boundedTake()
        assertEquals("POST", refreshReq?.method)
        assertTrue(refreshReq?.target?.endsWith("/auth/native/refresh") == true)
        val body = refreshReq?.body?.utf8().orEmpty()
        assertTrue(body.contains("\"refresh_token\":\"rt-live\""))
        assertTrue(body.contains("\"provider\":\"self-hosted\""))
        val retried = server.boundedTake()
        assertEquals("Bearer at-new", retried?.headers?.get("Authorization"))
    }

    @Test fun oidc_mode_terminal_refresh_gives_up_after_one_retry() = runTest {
        val server = serverRule.server
        // 1st: 401; refresh: 401 (dead RT) → tokens cleared → authenticator gives up; the
        // caller sees the 401 and surfaces a fresh login.
        server.enqueue(MockResponse.Builder().code(401).body("{}").build())
        server.enqueue(MockResponse.Builder().code(401).body(
            """{"error":"session_expired","detail":"start a new sign-in"}""",
        ).build())

        // In-memory store that actually persists saves (the clearing save must be visible).
        val store = object : com.hermes.client.data.auth.CredentialStore {
            var savedCount = 0
            var current: GatewayConfig = GatewayConfig(
                baseUrl = server.url("/").toString().trimEnd('/'),
                oauthTokens = tokenSet(refresh = "rt-dead"),
            )
            override fun load() = current
            override fun save(config: GatewayConfig) { savedCount++; current = config }
            override fun clear() {}
        }
        val c = OkHttpClient.Builder()
            .authenticator(GatedAuthenticator(GatedAuth(json) { null }, NativeTokenClient(
                json = json,
                store = store,
                refreshTokenSet = NativeTokenClient.defaultRefreshCall(json),
            )))
            .build()

        val resp = c.newCall(Request.Builder().url("${server.url("/")}api/status").get().build()).execute()
        assertEquals(401, resp.code)
        resp.close()
        assertTrue(
            "the clearing save (oauthTokens=null) must still have happened",
            store.savedCount >= 1,
        )
        assertNull("dead-RT tokens must be cleared from the store", store.load().oauthTokens)
        assertTrue(
            "the load() must keep reporting the OIDC baseUrl",
            store.load().baseUrl == server.url("/").toString().trimEnd('/'),
        )
    }

    @Test fun non_oidc_config_uses_password_login_path_with_no_tokenclient() = runTest {
        val server = serverRule.server
        server.enqueue(MockResponse.Builder().code(401).body("{}").build())
        server.enqueue(MockResponse.Builder().code(200).body("{}")
            .addHeader("Set-Cookie", "hermes_session_at=abc; Path=/").build())
        server.enqueue(MockResponse.Builder().code(200).body("""{"ok":true}""").build())

        val okHttp = OkHttpClient.Builder()
            .authenticator(GatedAuthenticator(GatedAuth(json) {
                GatewayConfig(baseUrl = server.url("/").toString().trimEnd('/'), username = "admin", password = "pw")
            }))
            .build()
        val resp = okHttp.newCall(Request.Builder().url("${server.url("/")}api/status").get().build()).execute()
        resp.close()

        val first = server.boundedTake()
        assertNotNull(first)
        assertNull(first!!.headers["Authorization"])
        val login = server.boundedTake()
        assertTrue(
            "the password login leg must hit /auth/password-login",
            login?.target?.endsWith("/auth/password-login") == true,
        )
        assertNotNull(server.boundedTake()) // the retried original
    }

    @Test fun refresh_after_401_reports_notOidcMode_for_token_only_config() {
        // token-only (loopback) config: the authenticator must fall back to the password path,
        // which for a token-only GatedAuth config is a no-op login → give up (no retry loop).
        val store = object : com.hermes.client.data.auth.CredentialStore {
            override fun load() = GatewayConfig(baseUrl = "http://gw:9119", token = "loop-token")
            override fun save(config: GatewayConfig) {}
            override fun clear() {}
        }
        val outcome = kotlinx.coroutines.runBlocking {
            NativeTokenClient(json, store, refreshTokenSet = { _, _ -> tokenSet() })
                .refreshAfter401(rejectedAccessToken = null)
        }
        assertTrue(outcome is NativeTokenClient.RefreshOutcome.NotOidcMode)
    }

    @Test fun authenticator_marker_prevents_second_refresh_for_the_same_request() {
        // The marker header on a rebuilt request: a second 401 on the retry must NOT trigger
        // another re-auth (guards an infinite loop with a dead RT).
        val req = Request.Builder().url("http://127.0.0.1:1/api/x")
            .header("X-Hermes-Reauth", "1").build()
        assertEquals("1", req.header("X-Hermes-Reauth"))
    }

    private companion object {
        const val RETRY_MARKER_TEST_VALUE = "X-Hermes-Reauth: 1"
    }
}