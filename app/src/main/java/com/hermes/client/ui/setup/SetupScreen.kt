package com.hermes.client.ui.setup

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

@Composable
fun SetupScreen(vm: SetupViewModel = hiltViewModel(), onSaved: () -> Unit) {
    val state by vm.state.collectAsStateWithLifecycle()
    val scanLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        // Null contents = the user cancelled or denied the camera; manual entry stays usable.
        result.contents?.let { vm.applyPairing(it) }
    }
    LaunchedEffect(state.saved) { if (state.saved) onSaved() }
    Column(
        // safeDrawingPadding keeps content clear of the status bar (clock/notifications)
        // and navigation bar under the enforced edge-to-edge display.
        Modifier.fillMaxSize().safeDrawingPadding().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Connect to Hermes", style = MaterialTheme.typography.headlineSmall)
        OutlinedButton(
            onClick = {
                scanLauncher.launch(
                    ScanOptions().apply {
                        setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        setPrompt("Scan the Hermes pairing QR")
                        setBeepEnabled(false)
                        setOrientationLocked(false)
                    },
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Scan QR") }
        state.scanError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        OutlinedTextField(
            value = state.url,
            onValueChange = vm::onUrlChange,
            label = { Text("Gateway URL (e.g. http://100.x.x.x:9119)") },
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
        state.oidcError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Text(
            "Opens your browser once to sign in; tokens are stored encrypted on this device.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        // ---------------- Advanced fallbacks (token / password) ----------------
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
                label = { Text("Token (loopback only — blank if using a password)") },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { vm.test() }) { Text("Test") }
            OutlinedButton(onClick = { vm.save() }) { Text("Save & continue") }
        }
        state.testResult?.let { Text(it) }
    }
}