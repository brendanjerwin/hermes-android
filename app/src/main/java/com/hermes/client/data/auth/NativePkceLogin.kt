package com.hermes.client.data.auth

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import com.hermes.client.data.diagnostics.DebugLog
import com.hermes.client.data.network.HermesApiException
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * RFC 8252 native-app login for Android, mirroring desktop `native-oauth-login.ts`:
 *
 * 1. bind a loopback HTTP listener on an ephemeral port (127.0.0.1 only — the gateway's
 *    `/auth/native/authorize` validates `redirect_uri` against loopback IP literals and
 *    rejects `localhost` per RFC 8252 §8.3);
 * 2. open the system browser (Custom Tab, falling back to ACTION_VIEW) at the gateway's
 *    `/auth/native/authorize` with our S256 PKCE challenge + loopback redirect_uri +
 *    CSRF state, `provider=self-hosted` (this gateway's OIDC provider);
 * 3. the gateway's own `/auth/callback` (browser-side web flow, no app-visible cookies)
 *    302s back to `http://127.0.0.1:<port>/callback?code=…&state=…`;
 * 4. verify state, then POST `/auth/native/token` with the code + PKCE verifier to get
 *    the bearer token set.
 *
 * Security posture (mirrors the desktop):
 *   - the listener is single-use: it shuts down the instant it accepted a redirect and
 *     redeems the code, or on timeout — no long-lived local listener;
 *   - `state` is verified before the code is redeemed; a mismatch is never redeemed;
 *   - the PKCE verifier never leaves the process until the token POST;
 *   - the browser sees only a minimal "you can close this window" page.
 *
 * The listener and exchange are injectable-free like the desktop's I/O shell: pure
 * decision logic lives in [NativeAuthLogic], this class owns the sockets.
 */
class NativePkceLogin(
    private val context: Context,
    private val json: Json,
) {
    /**
     * Drive a full native login against [baseUrl] and return the token set. Must run inside
     * the caller's IO-allowing dispatcher. Throws [NativeLoginException] on timeout, state
     * mismatch, a gateway error param, a token-exchange failure, or no browser to open.
     */
    suspend fun login(baseUrl: String, timeoutMs: Long = DEFAULT_LOGIN_TIMEOUT_MS): NativeTokenSet =
        withContext(Dispatchers.IO) {
            coroutineScope {
                val pair = NativeAuthLogic.generatePkcePair()
                val state = NativeAuthLogic.generateState()

                val server = LoopbackListener()
                // Bind before launching the browser so the redirect_uri port is known.
                val port = server.bind()
                val redirectUri = "http://127.0.0.1:$port/callback"
                val authorizeUrl = NativeAuthLogic.buildNativeAuthorizeUrl(
                    baseUrl = baseUrl,
                    challenge = pair.challenge,
                    redirectUri = redirectUri,
                    state = state,
                    provider = NativeAuthLogic.SELF_HOSTED_PROVIDER,
                )

                // Await the loopback redirect (or timeout) concurrently with opening the browser.
                val codeDeferred = async { server.awaitCallback(state, timeoutMs) }
                // Open the browser after the listener is up. Failures surface only if the
                // callback never arrives (a browser may still somehow complete the flow).
                val browserDeferred = async {
                    runCatching { openBrowser(authorizeUrl) }
                        .onFailure { DebugLog.log("auth", "browser launch failed: ${it.message}") }
                }

                try {
                    val code = codeDeferred.await()
                    browserDeferred.await()
                    exchangeToken(baseUrl, code, pair.verifier, redirectUri)
                } finally {
                    server.shutdown()
                }
            }
        }

    /**
     * Redeem [code] with the PKCE verifier at the gateway's token endpoint (the desktop's
     * postJsonNoAuth leg: cookieless by design, JSON object body, 15s timeout).
     */
    suspend fun exchangeToken(baseUrl: String, code: String, verifier: String, redirectUri: String): NativeTokenSet =
        withContext(Dispatchers.IO) {
            val url = NativeAuthLogic.nativeTokenUrl(baseUrl)
            val body = json.encodeToString(
                buildJsonObject {
                    put("code", code)
                    put("code_verifier", verifier)
                    put("redirect_uri", redirectUri)
                },
            )
            val client = OkHttpClient.Builder().callTimeout(15_000, java.util.concurrent.TimeUnit.MILLISECONDS).build()
            runCatching {
                client.newCall(
                    Request.Builder().url(url)
                        .post(body.toRequestBody("application/json".toMediaType()))
                        .build(),
                ).execute().use { resp ->
                    val respBody = resp.body?.string().orEmpty()
                    if (!resp.isSuccessful) {
                        throw NativeLoginException("Gateway token exchange failed: HTTP ${resp.code}")
                    }
                    NativeAuthLogic.parseTokenResponse(respBody, json)
                }
            }.getOrElse { e ->
                when (e) {
                    is HermesApiException, is CancellationException -> throw e
                    else -> throw NativeLoginException("Gateway token exchange failed: ${e.message ?: e.javaClass.simpleName}", e)
                }
            }
        }

    /** Open the authorize URL in the user's browser: Custom Tab when supported, else ACTION_VIEW. */
    private fun openBrowser(url: String) {
        val intent = CustomTabsIntent.Builder().build().intent
            .setData(Uri.parse(url))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching {
            context.startActivity(intent)
            return
        }
        // No Custom Tab activity resolved — fall back to a plain ACTION_VIEW.
        val fallback = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { context.startActivity(fallback) }
            .onFailure {
                throw NativeLoginException("No browser available for native sign-in")
            }
    }

    companion object {
        /** Matches the gateway's server-side pending-TTL (600s) — the desktop's login window. */
        const val DEFAULT_LOGIN_TIMEOUT_MS = 5 * 60 * 1000L
    }
}

/**
 * A single-use loopback HTTP receiver: binds 127.0.0.1 on an ephemeral port (restricted to
 * the RFC 8252 high-port range 49152-65535 per this fork's plan), serves the close page,
 * waits for the single `?code=…&state=…` GET the gateway's redirect produces, verifies
 * [awaitCallback]'s expected state, and shuts down. Any error param (including a
 * ?error= redirect) resolves the wait exceptionally.
 */
private class LoopbackListener {
    private val shutdown = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptJob: kotlinx.coroutines.Job? = null
    private val resultWaiter = Mutex()

    /** Bind 127.0.0.1:<port>; tries the preferred high-port range, falls back to ephemeral. Throws on bind failure. */
    fun bind(): Int {
        // Try the RFC 8252-ish high-port range first; any bind failure falls through to an
        // OS-assigned ephemeral port. Loopback-only binding is the security boundary —
        // binding 0.0.0.0 would let a network peer watch for the callback.
        for (port in PREFERRED_PORTS) {
            try {
                val ss = ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"))
                serverSocket = ss
                DebugLog.log("auth", "loopback listening on 127.0.0.1:$port")
                return port
            } catch (_: IOException) {
                // port in use — try the next
            }
        }
        val ss = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        serverSocket = ss
        val port = ss.localPort
        DebugLog.log("auth", "loopback listening on 127.0.0.1:$port (ephemeral)")
        return port
    }

    /**
     * Suspend until the one callback GET with ?code&state (or ?error=…) arrives, or the
     * [timeoutMs] elapses. Exactly ONE request is acted on; further connections get the
     * close page and no further callbacks. The listener is torn down in [shutdown].
     */
    suspend fun awaitCallback(expectedState: String, timeoutMs: Long): String {
        val ss = serverSocket ?: throw NativeLoginException("Loopback listener not bound")
        val result = kotlinx.coroutines.CompletableDeferred<String>()
        acceptJob = CoroutineScope(Dispatchers.IO).launch {
            while (!result.isCompleted && !shutdown.get()) {
                val socket: Socket = try {
                    ss.accept()
                } catch (e: IOException) {
                    if (!shutdown.get()) result.completeExceptionally(
                        NativeLoginException("Loopback listener failed: ${e.message ?: "IO error"}", e),
                    )
                    return@launch
                }
                handleConnection(socket, expectedState, result)
            }
        }
        try {
            return withTimeout(timeoutMs) { result.await() }
        } catch (e: TimeoutCancellationException) {
            throw NativeLoginException(
                "Native sign-in timed out. The browser window may not have completed sign-in; " +
                    "open Settings and try again.",
            )
        } finally {
            acceptJob?.cancel()
        }
    }

    /** Serve the close page for any request; complete [result] exactly once from the code-bearing GET. */
    private fun handleConnection(socket: Socket, expectedState: String, result: kotlinx.coroutines.CompletableDeferred<String>) {
        socket.use { s ->
            try {
                s.soTimeout = 10_000
                val input = s.getInputStream().bufferedReader(Charsets.ISO_8859_1)
                val requestLine = input.readLine().orEmpty()
                // Drain the rest of the request head so the socket does not hold keepalive state.
                while (true) {
                    val line = input.readLine() ?: break
                    if (line.isEmpty()) break
                }
                val target = requestLine.split(' ').getOrNull(1) ?: "/"
                if (target.contains("code=") || target.contains("error=")) {
                    if (!result.isCompleted) {
                        try {
                            result.complete(NativeAuthLogic.parseLoopbackCallback(target, expectedState))
                        } catch (e: Exception) {
                            result.completeExceptionally(e)
                        }
                    }
                }
                val done = DONE_HTML.toByteArray(Charsets.UTF_8)
                s.getOutputStream().apply {
                    write("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${done.size}\r\nConnection: close\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
                    write(done)
                    flush()
                }
            } catch (e: IOException) {
                // Browser aborted mid-request — nothing to serve; the waiter keeps waiting.
            }
        }
    }

    /** Idempotent shutdown of the single-use listener. */
    fun shutdown() {
        if (shutdown.compareAndSet(false, true)) {
            runCatching { serverSocket?.close() }
            acceptJob?.cancel()
        }
    }

    private companion object {
        /** The RFC 8252 high-port range recommended for native apps' loopback redirects. */
        val PREFERRED_PORTS = 49152..65535

        val DONE_HTML = """<!doctype html><meta charset="utf-8"><title>Signed in</title>""" +
            """<body style="font:15px system-ui;margin:3rem;text-align:center">""" +
            """<h2>&#10003; Signed in to Hermes</h2>""" +
            """<p>You can close this window and return to the app.</p>""" +
            """<script>setTimeout(()=>window.close(),800)</script>"""
    }
}