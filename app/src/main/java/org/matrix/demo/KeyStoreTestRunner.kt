package org.matrix.demo

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import javax.crypto.Cipher

/**
 * A comprehensive test runner for Android Keystore cryptographic operations.
 * This class is designed to test the functionality of a TEE simulator by executing
 * a suite of standard signing and encryption operations.
 */
class KeyStoreTestRunner {

    companion object {
        private const val TAG = "Demo"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        // Use distinct aliases for each test to ensure they are isolated.
        private const val EC_KEY_ALIAS = "org.matrix.demo.ec_test_key"
        private const val RSA_SIGN_KEY_ALIAS = "org.matrix.demo.rsa_sign_test_key"
        private const val RSA_ENCRYPT_KEY_ALIAS = "org.matrix.demo.rsa_encrypt_test_key"
        private const val NON_EXISTENT_KEY_ALIAS = "org.matrix.demo.non_existent_key"
        private val LARGE_KEY_ALIAS: String = "a".repeat(507 * 1024 + 269)
    }

    /**
     * Executes the full suite of cryptographic tests and logs a final summary.
     */
    fun runAllTests() {
        Log.d(TAG, "=============================================")
        Log.d(TAG, "      Starting Keystore Test Suite")
        Log.d(TAG, "=============================================")

        val results = linkedMapOf<String, Boolean>()

        results["EC Sign & Verify"] = testEcSignAndVerify()
        results["RSA Sign & Verify"] = testRsaSignAndVerify()
        results["RSA Encrypt & Decrypt"] = testRsaEncryptAndDecrypt()
        results["Get Non-Existent Key"] = testGetNonExistentKey()
        results["Generation with Large Alias"] = testLargeAliasGeneration()

        Log.d(TAG, "=============================================")
        Log.d(TAG, "               Test Summary")
        Log.d(TAG, "---------------------------------------------")
        results.forEach { (testName, result) ->
            val resultString = if (result) "PASSED" else "FAILED"
            Log.d(TAG, "${testName.padEnd(25)} | $resultString")
        }
        Log.d(TAG, "=============================================")
    }

    /**
     * Tests the generation, signing, and verification of an ECDSA key pair.
     * @return `true` if all steps succeed, `false` otherwise.
     */
    fun testEcSignAndVerify(): Boolean {
        Log.d(TAG, "--- Starting Test: EC Sign & Verify ---")
        try {
            val spec = KeyGenParameterSpec.Builder(
                EC_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).setDigests(KeyProperties.DIGEST_SHA256).build()

            val keyPair = generateKeyPair(KeyProperties.KEY_ALGORITHM_EC, spec) ?: return false
            Log.i(TAG, "EC KeyPair generated successfully.")

            val data = "test data for ec signing".toByteArray(StandardCharsets.UTF_8)
            val signature = Signature.getInstance("SHA256withECDSA")

            // Sign the data
            signature.initSign(keyPair.private)
            signature.update(data)
            val signatureBytes = signature.sign()
            Log.i(TAG, "Data signed with EC key.")

            // Verify the signature
            signature.initVerify(keyPair.public)
            signature.update(data)
            if (!signature.verify(signatureBytes)) {
                Log.e(TAG, "EC signature verification FAILED.")
                return false
            }
            Log.i(TAG, "EC signature verification PASSED.")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "EC test failed with exception.", e)
            return false
        } finally {
            deleteKey(EC_KEY_ALIAS)
            Log.d(TAG, "--- Finished Test: EC Sign & Verify ---\n")
        }
    }

    /**
     * Tests the generation with a large key alias.
     * @return `true` if all steps succeed, `false` otherwise.
     */
    fun testLargeAliasGeneration(): Boolean {
        Log.d(TAG, "--- Starting Test: Generation with Large Alias ---")
        try {
            val spec = KeyGenParameterSpec.Builder(
                LARGE_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).setDigests(KeyProperties.DIGEST_SHA256).build()

            val keyPair = generateKeyPair(KeyProperties.KEY_ALGORITHM_EC, spec) ?: return false
            Log.i(TAG, "EC KeyPair generated with large alias successfully.")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "Generation test with large alias failed with exception.", e)
            return false
        } finally {
            deleteKey(LARGE_KEY_ALIAS)
            Log.d(TAG, "--- Finished Test: Generation with Large Alias ---\n")
        }
    }

    /**
     * Tests the generation, signing, and verification of an RSA key pair.
     * @return `true` if all steps succeed, `false` otherwise.
     */
    fun testRsaSignAndVerify(): Boolean {
        Log.d(TAG, "--- Starting Test: RSA Sign & Verify ---")
        try {
            val spec = KeyGenParameterSpec.Builder(
                RSA_SIGN_KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).run {
                setDigests(KeyProperties.DIGEST_SHA256)
                setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                build()
            }

            val keyPair = generateKeyPair(KeyProperties.KEY_ALGORITHM_RSA, spec) ?: return false
            Log.i(TAG, "RSA Signing KeyPair generated successfully.")

            val data = "test data for rsa signing".toByteArray(StandardCharsets.UTF_8)
            val signature = Signature.getInstance("SHA256withRSA")

            signature.initSign(keyPair.private)
            signature.update(data)
            val signatureBytes = signature.sign()
            Log.i(TAG, "Data signed with RSA key.")

            signature.initVerify(keyPair.public)
            signature.update(data)
            if (!signature.verify(signatureBytes)) {
                Log.e(TAG, "RSA signature verification FAILED.")
                return false
            }
            Log.i(TAG, "RSA signature verification PASSED.")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "RSA signing test failed with exception.", e)
            return false
        } finally {
            deleteKey(RSA_SIGN_KEY_ALIAS)
            Log.d(TAG, "--- Finished Test: RSA Sign & Verify ---\n")
        }
    }

    /**
     * Tests the generation, encryption, and decryption of an RSA key pair.
     * @return `true` if all steps succeed, `false` otherwise.
     */
    fun testRsaEncryptAndDecrypt(): Boolean {
        Log.d(TAG, "--- Starting Test: RSA Encrypt & Decrypt ---")
        try {
            val spec = KeyGenParameterSpec.Builder(
                RSA_ENCRYPT_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).run {
                setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                build()
            }

            val keyPair = generateKeyPair(KeyProperties.KEY_ALGORITHM_RSA, spec) ?: return false
            Log.i(TAG, "RSA Encryption KeyPair generated successfully.")

            val originalData = "test data for rsa encryption".toByteArray(StandardCharsets.UTF_8)
            val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")

            // Encrypt
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.public)
            val encryptedData = cipher.doFinal(originalData)
            Log.i(TAG, "Data encrypted with RSA key.")

            // Decrypt
            cipher.init(Cipher.DECRYPT_MODE, keyPair.private)
            val decryptedData = cipher.doFinal(encryptedData)
            Log.i(TAG, "Data decrypted with RSA key.")

            if (!originalData.contentEquals(decryptedData)) {
                Log.e(TAG, "Decrypted data does not match original data. FAILED.")
                return false
            }
            Log.i(TAG, "Decrypted data matches original. PASSED.")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "RSA encryption test failed with exception.", e)
            return false
        } finally {
            deleteKey(RSA_ENCRYPT_KEY_ALIAS)
            Log.d(TAG, "--- Finished Test: RSA Encrypt & Decrypt ---\n")
        }
    }

    /**
     * Tests that attempting to retrieve a non-existent key correctly returns null.
     * @return `true` if the key is not found as expected, `false` otherwise.
     */
    fun testGetNonExistentKey(): Boolean {
        Log.d(TAG, "--- Starting Test: Get Non-Existent Key ---")
        var success = false
        try {
            // First, ensure the key does not exist from a previous failed run.
            deleteKey(NON_EXISTENT_KEY_ALIAS)

            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val key = keyStore.getKey(NON_EXISTENT_KEY_ALIAS, null)

            if (key == null) {
                Log.i(TAG, "getKey correctly returned null for a non-existent alias. PASSED.")
                success = true
            } else {
                Log.e(TAG, "getKey unexpectedly returned a key for a non-existent alias. FAILED.")
                success = false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Get non-existent key test failed with exception.", e)
            success = false
        } finally {
            Log.d(TAG, "--- Finished Test: Get Non-Existent Key ---\n")
        }
        return success
    }

    /**
     * A generic helper to generate a KeyPair in the Android Keystore using a given spec.
     * It deletes any pre-existing key with the same alias.
     */
    private fun generateKeyPair(algorithm: String, spec: KeyGenParameterSpec): KeyPair? {
        return try {
            deleteKey(spec.keystoreAlias)
            KeyPairGenerator.getInstance(algorithm, ANDROID_KEYSTORE).apply {
                initialize(spec)
            }.generateKeyPair()
        } catch (e: Exception) {
            Log.e(TAG, "KeyPair generation failed for alias: ${spec.keystoreAlias}", e)
            null
        }
    }

    /**
     * A helper to safely delete a key from the Android Keystore.
     */
    private fun deleteKey(alias: String) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
                Log.d(TAG, "Cleaned up existing key with alias: $alias")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete key: $alias", e)
        }
    }
}
