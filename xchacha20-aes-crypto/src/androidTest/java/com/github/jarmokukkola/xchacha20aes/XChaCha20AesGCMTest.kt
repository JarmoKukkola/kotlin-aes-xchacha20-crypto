package com.github.jarmokukkola.xchacha20aes

import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.decryptString
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.encrypt
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.generateKey
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.generateKeyFromPasswordArgon2
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.generateKeyFromPasswordPBKDF2
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.generateSalt
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.keyString
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.keys
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.saltString
import com.ionspin.kotlin.crypto.LibsodiumInitializer
import com.ionspin.kotlin.crypto.secretstream.SecretStream
import com.ionspin.kotlin.crypto.util.encodeToUByteArray
import junit.framework.TestCase
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

class XChaCha20AesGCMTest {

    @Test
    fun encryptAndDecryptText() {
        val keys = generateKey()

        val testString = "some test"

        val cipherTextIvHeader = encrypt(testString,keys)
        val ciphertextString = cipherTextIvHeader.toString()  //store or send to server //store or send to server

        //decrypt
        val plainText = decryptString(cipherTextIvHeader,keys)

        TestCase.assertEquals(testString,plainText)
    }

    @Test
    fun passwordGeneratedPBKDF2KeysEqual() {
        val salt = generateSalt()
        val password = "dt43fndg5¤%fDG43213ngds!!%#¤%"
        val key1 = generateKeyFromPasswordPBKDF2(password,salt)
        val key2 = generateKeyFromPasswordPBKDF2(password,salt)
        TestCase.assertEquals(key1,key2)
    }

    @Test
    fun passwordGeneratedPBKDF2KeysEqual2() {
        val salt = generateSalt()
        val password = "dt43fndg5¤%fDG43213ngds!!%#¤%"
        val key1 = generateKeyFromPasswordPBKDF2(password,salt)
        val key2 = generateKeyFromPasswordPBKDF2(password,saltString(salt))
        TestCase.assertEquals(key1,key2)
    }

    @Test
    fun passwordGeneratedArgon2KeysEqual() {
        val salt = generateSalt()
        val password = "dt43fndg5¤%fDG43213ngds!!%#¤%"
        val key1 = generateKeyFromPasswordArgon2(password,salt)
        val key2 = generateKeyFromPasswordArgon2(password,salt)
        TestCase.assertEquals(key1,key2)
    }

    @Test
    fun passwordGeneratedArgon2KeysEqual2() {
        val salt = generateSalt()
        val password = "dt43fndg5¤%fDG43213ngds!!%#¤%"
        val key1 = generateKeyFromPasswordArgon2(password,salt)
        val key2 = generateKeyFromPasswordArgon2(password,saltString(salt))
        TestCase.assertEquals(key1,key2)
    }

    @Test
    fun AesGCMTest() {
        val testText = "some test"
        val secretKeys = generateKey()
        var ivGCM = XChaCha20AesGCM.generateIv()
        val aesCipherForEncryptionGCM = Cipher.getInstance(XChaCha20AesGCM.CIPHER_TRANSFORMATION)
        aesCipherForEncryptionGCM.init(Cipher.ENCRYPT_MODE,secretKeys.confidentialityKeyAes,IvParameterSpec(ivGCM))
        ivGCM = aesCipherForEncryptionGCM.iv
        val byteCipherTextGCM = aesCipherForEncryptionGCM.doFinal(testText.toByteArray(Charsets.UTF_8))
        val aesCipherForDecryptionGCM = Cipher.getInstance(XChaCha20AesGCM.CIPHER_TRANSFORMATION)
        aesCipherForDecryptionGCM.init(
            Cipher.DECRYPT_MODE,secretKeys.confidentialityKeyAes,IvParameterSpec(ivGCM)
        )
        val cipherTextGCM = aesCipherForDecryptionGCM.doFinal(byteCipherTextGCM).toString(Charsets.UTF_8)
        TestCase.assertEquals(testText,cipherTextGCM)
    }

    @Test
    fun stringifyKeys() {
        val keys = generateKey()
        val keysText = keyString(keys)
        val restoredKeys = keys(keysText)
        TestCase.assertEquals(keys,restoredKeys)
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    @Test
    fun chaCha20() {
        LibsodiumInitializer.initializeWithCallback {
            val value = "someText"

            val key = generateKey().confidentialityKeyChaCha20.toString().encodeToUByteArray()

            var secretStreamStateAndHeader = SecretStream.xChaCha20Poly1305InitPush(key)

            val encrypted = SecretStream.xChaCha20Poly1305Push(
                secretStreamStateAndHeader.state,value.encodeToUByteArray(),ubyteArrayOf(),0U
            )

            secretStreamStateAndHeader = SecretStream.xChaCha20Poly1305InitPull(key,secretStreamStateAndHeader.header)
            val decrypted = SecretStream.xChaCha20Poly1305Pull(
                secretStreamStateAndHeader.state,encrypted,ubyteArrayOf()
            ).decryptedData.toByteArray().toString(Charsets.UTF_8)

            TestCase.assertEquals(value,decrypted)
        }
    }
}