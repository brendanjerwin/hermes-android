package com.hermes.client.ui.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hermes.client.data.auth.CredentialStore
import com.hermes.client.data.auth.GatewayConfig
import com.hermes.client.data.auth.NativeLoginException
import com.hermes.client.data.auth.NativePkceLogin
import com.hermes.client.data.network.GatedAuth
import com.hermes.client.data.network.HermesRestApi
import com.hermes.client.data.repository.ChatRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.withContext
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

data class ConnectionUiState(
    val url: String = "",
    val token: String = "",
    val username: String = "",
    val password: String = "",
    val testResult: String? = null,
    val saved: Boolean = false,
    /** Status line for the OIDC flow (spinner state / result / error). */
    val oidcStatus: String? = null,
    /** True when [oidcStatus] is an error (coloured in the screen). */
    val oidcError: String? = null,
    val oidcInProgress: Boolean = false,
    /** Token/password fallback fields collapsed behind "Advanced". */
    val showAdvanced: Boolean = false,
)

/**
 * View/update the gateway URL + sign-in mode after first-run setup. Mirrors SetupViewModel
 * but is reachable from Settings and reconnects the live socket on save so a changed
 * server/credential takes effect without restarting the app.
 */
@HiltViewModel
class ConnectionSettingsViewModel @Inject constructor(
    private val store: CredentialStore,
    private val rest: HermesRestApi,
    private val chat: ChatRepository,
    private val gatedAuth: GatedAuth,
    private val nativePkceLogin: NativePkceLogin,
) : ViewModel() {
    private val _state = MutableStateFlow(
        store.load()?.let {
            ConnectionUiState(
                url = it.baseUrl, token = it.token, username = it.username, password = it.password,
                oidcStatus = if (it.isOidc) "Signed in via OIDC as ${it.oauthTokens?.userId.orEmpty().ifBlank { "…" }}" else null,
                showAdvanced = it.isOidc.not() && (it.token.isNotBlank() || it.isGated),
            )
        } ?: ConnectionUiState(),
    )
    val state: StateFlow<ConnectionUiState> = _state.asStateFlow()

    private var oidcJob: Job? = null

    fun onUrlChange(v: String) { _state.value = _state.value.copy(url = v.trim(), saved = false, testResult = null) }
    fun onTokenChange(v: String) { _state.value = _state.value.copy(token = v.trim(), saved = false, testResult = null) }
    fun onUsernameChange(v: String) { _state.value = _state.value.copy(username = v.trim(), saved = false, testResult = null) }
    fun onPasswordChange(v: String) { _state.value = _state.value.copy(password = v, saved = false, testResult = null) }
    fun toggleAdvanced() { _state.value = _state.value.copy(oidcError = null, showAdvanced = !_state.value.showAdvanced) }

    /** Test with the entered values WITHOUT persisting: a login probe when a username is set,
     *  otherwise a plain status check. */
    fun test() = viewModelScope.launch {
        val s = _state.value
        val ok = if (s.username.isNotBlank()) {
            withContext(Dispatchers.IO) { gatedAuth.probeLogin(s.url, s.username, s.password) }
        } else {
            rest.statusFor(s.url, s.token)
        }
        _state.value = _state.value.copy(testResult = if (ok) "Connected ✓" else "Failed — check the details")
    }

    /**
     * Run the RFC 8252 native login end-to-end (browser → loopback redirect → token
     * exchange) and save an OIDC-mode config, then reconnect. Mutually exclusive with the
     * token and password modes — the OIDC credential wins.
     */
    fun signInWithOidc() {
        if (_state.value.oidcInProgress) return
        val url = _state.value.url
        if (url.isBlank()) {
            _state.value = _state.value.copy(oidcStatus = "Enter the gateway URL first", oidcError = "Enter the gateway URL first")
            return
        }
        oidcJob = viewModelScope.launch {
            _state.value = _state.value.copy(oidcInProgress = true, oidcError = null, oidcStatus = "Waiting for sign-in…")
            try {
                val tokens = nativePkceLogin.login(url)
                store.save(
                    GatewayConfig(
                        baseUrl = url,
                        oauthTokens = tokens,
                        // Mutually exclusive modes: the OIDC credential wins.
                        token = "", username = "", password = "",
                    ),
                )
                gatedAuth.cookieJar.clear()
                _state.value = _state.value.copy(
                    oidcInProgress = false, oidcError = null,
                    oidcStatus = "Signed in via OIDC as ${tokens.userId.ifBlank { "…" }} — reconnecting",
                    showAdvanced = false,
                )
                save()
            } catch (e: kotlinx.coroutines.CancellationException) {
                _state.value = _state.value.copy(oidcInProgress = false)
                throw e
            } catch (e: Exception) {
                _state.value = _state.value.copy(
                    oidcInProgress = false,
                    oidcError = oidcErrorMessage(e),
                    oidcStatus = oidcErrorMessage(e),
                )
            }
        }
    }

    /** Persist the new server/credentials, drop any stale session, then reconnect. */
    fun save() {
        val s = _state.value
        store.save(GatewayConfig(s.url.trim(), s.token.trim(), s.username.trim(), s.password))
        gatedAuth.cookieJar.clear() // force a fresh login with the new credentials
        runCatching { chat.reconnect() }
        _state.value = _state.value.copy(saved = true, testResult = "Saved — reconnecting")
    }

    /** Cancel an in-flight browser login (user backed out); the loopback listener is torn down. */
    override fun onCleared() {
        oidcJob?.cancel()
        super.onCleared()
    }

    private fun oidcErrorMessage(e: Exception): String = when {
        e is NativeLoginException && e.message?.contains("timed out", ignoreCase = true) == true ->
            "Sign-in timed out — the browser may not have completed login. Try again."
        else -> e.message ?: "Sign-in failed"
    }
}