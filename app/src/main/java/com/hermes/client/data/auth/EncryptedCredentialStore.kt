package com.hermes.client.data.auth

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.hermes.client.data.diagnostics.DebugLog
import kotlinx.serialization.json.Json

/**
 * Concrete secure storage backed by EncryptedSharedPreferences (security-crypto 1.0.0).
 * If migrating to a newer backend later, only this file changes — callers depend on the
 * CredentialStore interface.
 *
 * The RFC 8252 OAuth token set is serialized as the camelCase [NativeTokenSet] JSON inside
 * the same encrypted prefs — the desktop's safeStorage-boundary equivalent. The stored
 * direction uses NativeAuthLogic.parseStoredTokenSet never parseTokenResponse (crossing the
 * two broke the desktop on every restart, #73271).
 */
class EncryptedCredentialStore(private val context: Context) : CredentialStore {
    // EncryptedSharedPreferences keeps its Tink keyset inside this same prefs file. If that keyset
    // is corrupted (e.g. an interrupted write or an app upgrade), create() throws
    // InvalidProtocolBufferException and the app crashes on EVERY launch — before any UI. Recover
    // by wiping the backing file once and regenerating a fresh keyset: the saved credentials are
    // lost (the user re-enters them on the Setup screen), which is far better than a crash loop.
    private val prefs by lazy { openOrReset() }

    private fun create(): SharedPreferences {
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        return EncryptedSharedPreferences.create(
            PREFS_NAME,
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    private fun openOrReset(): SharedPreferences =
        try {
            create()
        } catch (e: Exception) {
            // Corrupt/unreadable keyset. EncryptedSharedPreferences stores its keyset inside the
            // PREFS_NAME file, so deleting that and recreating recovers it (verified on a physical
            // device). If a second attempt still fails the corruption is deeper — the master key in
            // the Android keystore — so drop that too and regenerate everything, guaranteeing we
            // never crash-loop on launch.
            DebugLog.log("auth", "credential store unreadable, resetting: ${e.javaClass.simpleName}")
            runCatching { context.deleteSharedPreferences(PREFS_NAME) }
            try {
                create()
            } catch (e2: Exception) {
                DebugLog.log("auth", "reset insufficient, clearing master key: ${e2.javaClass.simpleName}")
                runCatching {
                    java.security.KeyStore.getInstance("AndroidKeyStore")
                        .apply { load(null) }
                        .deleteEntry(MASTER_KEY_ALIAS)
                }
                runCatching { context.deleteSharedPreferences(PREFS_NAME) }
                create()
            }
        }

    override fun load(): GatewayConfig? {
        val url = prefs.getString("base_url", null) ?: return null
        return GatewayConfig(
            baseUrl = url,
            token = prefs.getString("token", null) ?: "",
            username = prefs.getString("username", null) ?: "",
            password = prefs.getString("password", null) ?: "",
            oauthTokens = prefs.getString("oauth_tokens", null)?.let { raw ->
                runCatching {
                    // Stored blobs are normalized camelCase sets, never raw gateway responses.
                    NativeAuthLogic.parseStoredTokenSet(raw, tokenJson)
                }.onFailure {
                    DebugLog.log("auth", "stored oauth tokens unreadable, dropping: ${it.message}")
                }.getOrNull()
            },
        )
    }

    override fun save(config: GatewayConfig) {
        prefs.edit()
            .putString("base_url", config.baseUrl)
            .putString("token", config.token)
            .putString("username", config.username)
            .putString("password", config.password)
            .putString(
                "oauth_tokens",
                config.oauthTokens?.let { tokenJson.encodeToString(NativeTokenSet.serializer(), it) },
            )
            .apply()
    }

    override fun clear() {
        prefs.edit().clear().apply()
    }

    private companion object {
        const val PREFS_NAME = "hermes_credentials"
        // Default Android-keystore alias used by MasterKeys.AES256_GCM_SPEC (the constant itself is
        // package-private). Deleting this entry forces a fresh master key if the keyset reset alone
        // didn't recover.
        const val MASTER_KEY_ALIAS = "_androidx_security_master_key_"
        val tokenJson = Json { ignoreUnknownKeys = true }
    }
}
