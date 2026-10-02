package com.hermes.client.ui.settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectionSettingsScreen(
    onBack: () -> Unit,
    vm: ConnectionSettingsViewModel = hiltViewModel(),
) {
    val state by vm.state.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            com.hermes.client.ui.components.HermesTopBar(
                title = "Server & sign-in",
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "The Hermes dashboard this app connects to. Sign in with OIDC (recommended) " +
                    "opens your browser once; advanced fallbacks use a password (network " +
                    "dashboard) or a session token (local/loopback). Save to reconnect.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.url,
                onValueChange = vm::onUrlChange,
                label = { Text("Gateway URL (e.g. http://100.x.x.x:9119)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            // ---------------- Recommended: OIDC sign in ----------------
            Button(
                onClick = { vm.signInWithOidc() },
                enabled = !state.oidcInProgress && state.url.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (state.oidcInProgress) {
                    CircularProgressIndicator(
                        modifier = Modifier.padding(end = 8.dp),
                        strokeWidth = 2.dp,
                    )
                    Text("Waiting for sign-in…")
                } else {
                    Text("Sign in with OIDC (recommended)")
                }
            }
            state.oidcStatus?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodyMedium,
                    color = state.oidcError?.let { _ -> MaterialTheme.colorScheme.error }
                        ?: MaterialTheme.colorScheme.onSurface,
                )
            }
            // ---------------- Advanced fallbacks ----------------
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                IconButton(onClick = { vm.toggleAdvanced() }) {
                    Icon(
                        if (state.showAdvanced) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
                        contentDescription = if (state.showAdvanced) "Hide advanced options" else "Show advanced options",
                    )
                }
                Text("Advanced", style = MaterialTheme.typography.labelLarge)
            }
            if (state.showAdvanced) {
                OutlinedTextField(
                    value = state.username,
                    onValueChange = vm::onUsernameChange,
                    label = { Text("Username (for password-protected dashboards)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = state.password,
                    onValueChange = vm::onPasswordChange,
                    label = { Text("Password") },
                    singleLine = true,
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = state.token,
                    onValueChange = vm::onTokenChange,
                    label = { Text("Token (loopback only — leave blank if using a password)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { vm.test() }) { Text("Test") }
                OutlinedButton(onClick = { vm.save() }) { Text("Save & reconnect") }
            }
            state.testResult?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        }
    }
}