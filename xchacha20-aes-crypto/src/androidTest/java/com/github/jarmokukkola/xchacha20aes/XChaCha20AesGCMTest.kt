package com.github.jarmokukkola.xchacha20aes

import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.IV_LENGTH_BYTES
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.decrypt
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.decryptString
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.encrypt
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.generateKey
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.generateKeyFromPassword
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
import org.junit.Assert
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.OutputStream
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import kotlin.random.Random

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

    @Test
    fun byteWriteTest() {
        val byteArray = Random.nextBytes(20)
        var text = ByteArray(0)
        byteArray.forEach {
            val number = it.toInt()
            text += number.toByte()
        }
        Assert.assertEquals(byteArray.toString(Charsets.UTF_8),text.toString(Charsets.UTF_8))
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    @Test
    fun streamEncryptDecrypt() {
        val bufferSize = 1000
        val text = Random.nextBytes(20010).toString(Charsets.UTF_8)
        val size = text.length
        val inputStream = text.byteInputStream(Charsets.UTF_8)
        val outputStream = getOutPutStream()

        val secretKeys = generateKey()

        if(!LibsodiumInitializer.isInitialized()) {
            LibsodiumInitializer.initializeWithCallback {}
        }

        val key = secretKeys.confidentialityKeyChaCha20.toString().encodeToUByteArray()
        val aesCipherForEncryptionGCM = Cipher.getInstance(XChaCha20AesGCM.CIPHER_TRANSFORMATION)

        /*
             * Now we get back the IV that will actually be used. Some Android
             * versions do funny stuff w/ the IV, so this is to work around bugs:
             */ //        iv = aesCipherForEncryptionGCM.iv

        val listener = getStreamListener()

        try {

            var buffer = ByteArray(bufferSize)
            var bytesCopied:Long = 0
            var read = inputStream.read(buffer)
            while(read>=0) {
                val secretStreamStateAndHeader = SecretStream.xChaCha20Poly1305InitPush(key)
                val byteCipherTextChaCha20 = SecretStream.xChaCha20Poly1305Push(
                    secretStreamStateAndHeader.state,buffer.run {
                        if(read==bufferSize) {
                            this
                        } else {
                            copyOfRange(0,read)
                        }
                    }.toUByteArray(),ubyteArrayOf(),0U
                ).toByteArray()
                val iv = XChaCha20AesGCM.generateIv()
                aesCipherForEncryptionGCM.init(Cipher.ENCRYPT_MODE,secretKeys.confidentialityKeyAes,IvParameterSpec(iv))
                val byteCipherTextGCM = aesCipherForEncryptionGCM.doFinal(byteCipherTextChaCha20)
                outputStream.write(iv)
                outputStream.write(secretStreamStateAndHeader.header.toByteArray())
                outputStream.write(byteCipherTextGCM)
                bytesCopied += read
                listener.onProgress(read,bytesCopied,size.toLong())
                read = inputStream.read(buffer)
            }
            val encrypted = outputStream.toByteArray()

            val inputStream = ByteArrayInputStream(encrypted)
            outputStream.clear() //
            val header = ByteArray(24)

            val aesCipherForDecryptionGCM = Cipher.getInstance(XChaCha20AesGCM.CIPHER_TRANSFORMATION)

            buffer = ByteArray(bufferSize+24)
            bytesCopied = 0
            val iv = ByteArray(IV_LENGTH_BYTES)
            inputStream.read(iv)
            inputStream.read(header)
            read = inputStream.read(buffer)
            while(read>=0) {
                val value = if(read==buffer.size) {
                    buffer
                } else {
                    buffer.copyOf(read)
                }
                aesCipherForDecryptionGCM.init(
                    Cipher.DECRYPT_MODE,secretKeys.confidentialityKeyAes,IvParameterSpec(iv)
                )
                val cipherTextGCM = aesCipherForDecryptionGCM.doFinal(value)
                val secretStreamStateAndHeader = SecretStream.xChaCha20Poly1305InitPull(
                    key,header.toUByteArray()
                )
                val block = SecretStream.xChaCha20Poly1305Pull(
                    secretStreamStateAndHeader.state,cipherTextGCM.toUByteArray(),ubyteArrayOf()
                ).decryptedData.toByteArray()

                outputStream.write(block)
                bytesCopied += read
                listener.onProgress(read,bytesCopied,size.toLong())
                inputStream.read(iv)
                inputStream.read(header)
                read = inputStream.read(buffer)
            }

            TestCase.assertEquals(text,outputStream.toByteArray().toString(Charsets.UTF_8))
        } catch(e:IOException) {
            listener.onFailure("Cannot write outPutStream",e)
        } finally {
            outputStream.flush()
            outputStream.close()
            inputStream.close()
        }
    }

    @Test
    fun streamEncryptDecrypt2() {
        val keys = generateKey()
        val text = Random.nextBytes(20010).toString(Charsets.UTF_8)
        val size = text.length.toLong()
        val bufferSize =100 * 1024
        var inputStream = text.byteInputStream(Charsets.UTF_8)
        val outputStream = getOutPutStream()
        encrypt(inputStream,outputStream,keys,size,getStreamListener(),bufferSize)
        val encrypted = outputStream.toByteArray()

        inputStream = encrypted.inputStream()
        outputStream.clear()

        decrypt(inputStream,outputStream,keys,size,getStreamListener(),bufferSize)

        val decrypted = outputStream.toByteArray().toString(Charsets.UTF_8)
        TestCase.assertEquals(decrypted,text)
        TestCase.assertNotSame(encrypted,text)
    }

    @Test
    fun generateKeyFromPasswordTimeTest() {
        val password = "gfdgk234mgbdflk3"
        val salt = generateSalt()
        val time = GregorianCalendar().timeInMillis
        generateKeyFromPassword(password,salt)
        val duration = GregorianCalendar().timeInMillis-time
        TestCase.assertTrue(duration>500)
        TestCase.assertTrue(duration<2000)
    }

    private fun getStreamListener() = object:StreamListener {
        override fun <T> onSuccess(result:T) {}
        override fun onFailure(message:String,e:Exception) {}
    }

    private fun getOutPutStream() = object:OutputStream() {
        private var value = ByteArray(0)

        @Throws(IOException::class)
        override fun write(b:Int) {
            value += b.toByte()
        }

        override fun write(b:ByteArray) {
            value += b
        }

        fun toByteArray() = value.copyOf()

        fun clear() {
            value = ByteArray(0)
        }
    }
}