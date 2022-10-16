/*
 * Copyright (c) 2014-2015 Tozny LLC, 2022 Jarmo Kukkola
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Created by Isaac Potoczny-Jones on 11/12/14, Modified by Jarmo Kukkola on 3/10/22.
 */
package com.github.jarmokukkola.xchacha20aes

import android.os.Build
import android.os.Process
import android.util.Base64
import android.util.Log
import com.ionspin.kotlin.crypto.LibsodiumInitializer
import com.ionspin.kotlin.crypto.pwhash.PasswordHash
import com.ionspin.kotlin.crypto.pwhash.crypto_pwhash_argon2id_ALG_ARGON2ID13
import com.ionspin.kotlin.crypto.secretstream.SecretStream
import com.ionspin.kotlin.crypto.util.encodeToUByteArray
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.UnsupportedEncodingException
import java.nio.charset.Charset
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.Provider
import java.security.SecureRandom
import java.security.SecureRandomSpi
import java.security.Security
import java.security.spec.KeySpec
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Simple library for the XChaCha20/AES key generation, encryption, and decryption.
 * This library encrypts plain text first using (256-bit AES, GCM, No padding) and then
 * result is again encrypted with (XChaCha20, Poly1305).
 */
@OptIn(ExperimentalUnsignedTypes::class)
object XChaCha20AesGCM {
    // If the PRNG fix would not succeed for some reason, we normally will throw an exception.
    // If ALLOW_BROKEN_PRNG is true, however, we will simply log instead.
    private const val ALLOW_BROKEN_PRNG = false
    const val CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding"
    private const val CIPHER = "AES"
    private const val AES_KEY_LENGTH_BITS = 256
    const val IV_LENGTH_BYTES = 16
    const val PBE_ITERATION_COUNT = 50000
    private val PBE_ALGORITHM = PbeAlgorithm.PBKDF2WithHmacSHA1
    private const val PBE_SALT_LENGTH_BITS = AES_KEY_LENGTH_BITS // same size as key output
    private const val OPS_LIMIT_ARGON2 = 64UL
    private const val MEM_LIMIT_ARGON2 = 16*1024*1024
    private const val BUFFER_SIZE = 100*1024

    //Made BASE_64_FLAGS public as it's useful to know for compatibility.
    const val BASE64_FLAGS = Base64.NO_WRAP

    //default for testing
    val prngFixed = AtomicBoolean(false)

    /**
     * Converts the given XChaCha20/AES keys into a base64 encoded string suitable for
     * storage. Sister function of keys.
     *
     * @param keys The combined XChaCha20 and AES keys
     * @return a base 64 encoded XChaCha20 key and AES key as base64(xChaCha20Key):base64(aesKey)
     */
    @JvmStatic
    fun keyString(keys:SecretKeys):String {
        return keys.toString()
    }

    /**
     * A XChaCha20 key and AES key derived from a base64 encoded key. This does not generate the
     * key. It's not random or a PBE key.
     *
     * @param keysStr a base64 encoded XChaCha20 key and AES key as base64(xChaCha20Key):base64(aesKey).
     * @return XChaCha20 key and AES key set suitable for other functions.
     */
    @JvmStatic
    @Throws(InvalidKeyException::class)
    fun keys(keysStr:String):SecretKeys {
        val keysArr = keysStr.split(":").toTypedArray()
        return if(keysArr.size!=2) {
            throw IllegalArgumentException("Cannot parse xChaCha20Key:aesKey")
        } else {
            val confidentialityKeyChaCha20 = Base64.decode(keysArr[0],BASE64_FLAGS)
            if(confidentialityKeyChaCha20.size!=AES_KEY_LENGTH_BITS/8) {
                throw InvalidKeyException("Base64 decoded key is not $AES_KEY_LENGTH_BITS bytes")
            }
            val confidentialityKeyGCM = Base64.decode(keysArr[1],BASE64_FLAGS)
            if(confidentialityKeyGCM.size!=AES_KEY_LENGTH_BITS/8) {
                throw InvalidKeyException("Base64 decoded GCM key is not $AES_KEY_LENGTH_BITS bytes")
            }
            SecretKeys(
                SecretKeySpec(confidentialityKeyChaCha20,0,confidentialityKeyChaCha20.size,CIPHER),
                SecretKeySpec(confidentialityKeyGCM,0,confidentialityKeyGCM.size,CIPHER)
            )
        }
    }

    /**
     * A function that generates random XChaCha20 and AES keys and prints out exceptions but
     * doesn't throw them since none should be encountered. If they are
     * encountered, the return value is null.
     *
     * @return The XChaCha20 and AES keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     * or a suitable RNG is not available
     */
    @JvmStatic
    @Throws(GeneralSecurityException::class)
    fun generateKey():SecretKeys {
        fixPrng()
        val keyGen = KeyGenerator.getInstance(CIPHER) // No need to provide a SecureRandom or set a seed since that will // happen automatically.
        keyGen.init(AES_KEY_LENGTH_BITS)
        val confidentialityKeyChaCha20 = keyGen.generateKey()
        val confidentialityKeyGCM = keyGen.generateKey()
        return SecretKeys(confidentialityKeyChaCha20,confidentialityKeyGCM)
    }

    /**
     * A function to initialized Libsodium library
     **/

    private fun <T> initializeLibsodium(callback:()->T):T {
        if(!LibsodiumInitializer.isInitialized()) {
            LibsodiumInitializer.initializeWithCallback {}
        }
        return callback.invoke()
    }

    /**
     * A function that generates password-based XChaCha20 and AES keys with Argon2_ID + PBKDF2.
     *
     * @param password The password to derive the keys from.
     * @param salt Unique salt
     * @param opsLimit maximum amount of Argon2 computations to perform.
     * @param memLimitArgon2 maximum amount of RAM in bytes that the Argon2 function will use.
     * @param pbeIterationCount is iteration count of PBKDF2.
     * @param pbeAlgorithm is PBKDF2 key derivation algorithm
     * @return The XChaCha20 and AES keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     * or a suitable RNG is not available
     */
    @Throws(GeneralSecurityException::class)
    fun generateKeyFromPassword(
        password:String,
        salt:ByteArray,
        opsLimit:ULong = OPS_LIMIT_ARGON2,
        memLimitArgon2:Int = MEM_LIMIT_ARGON2,
        pbeIterationCount:Int = PBE_ITERATION_COUNT,
        pbeAlgorithm:PbeAlgorithm = PBE_ALGORITHM
    ):SecretKeys {
        fixPrng() //Get enough random bytes for both the AES key and the ChaCha20 key:
        return initializeLibsodium {
            generateKeyFromPasswordArgon2(password,salt,opsLimit,memLimitArgon2).toString().run {
                generateKeyFromPasswordPBKDF2(this,salt,pbeIterationCount,pbeAlgorithm)
            }
        }
    }

    /**
     * A function that generates password-based XChaCha20 and AES keys with Argon2_ID.
     *
     * @param password The password to derive the keys from.
     * @param salt Unique salt
     * @param opsLimit maximum amount of computations to perform.
     * @param memLimitArgon2 maximum amount of RAM in bytes that the function will use.
     * @return The XChaCha20 and AES keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     * or a suitable RNG is not available
     */
    @Throws(GeneralSecurityException::class)
    fun generateKeyFromPasswordArgon2(
        password:String,salt:ByteArray,opsLimit:ULong = OPS_LIMIT_ARGON2,memLimitArgon2:Int = MEM_LIMIT_ARGON2
    ):SecretKeys {
        fixPrng() //Get enough random bytes for both the AES key and the ChaCha20 key:
        var keyBytes = initializeLibsodium {
            PasswordHash.pwhash(
                AES_KEY_LENGTH_BITS*2,password,salt.toUByteArray(),opsLimit,memLimitArgon2,crypto_pwhash_argon2id_ALG_ARGON2ID13
            ).toByteArray()
        }

        // Split the random bytes into two parts:
        val confidentialityKeyBytes = copyOfRange(keyBytes,0,AES_KEY_LENGTH_BITS/8)
        val confidentialityKeyBytesGCM = copyOfRange(
            keyBytes,AES_KEY_LENGTH_BITS/88,2*AES_KEY_LENGTH_BITS/8
        )

        //Generate the XChaCha20 key
        val confidentialityKeyChaCha20:SecretKey = SecretKeySpec(confidentialityKeyBytes,CIPHER)

        //Generate the AES-GCM key
        val confidentialityKeyGCM:SecretKey = SecretKeySpec(confidentialityKeyBytesGCM,CIPHER)
        return SecretKeys(confidentialityKeyChaCha20,confidentialityKeyGCM)
    }

    /**
     * A function that generates password-based XChaCha20 and AES keys with PBKDF2.
     * @param password The password to derive the XChaCha20/AES keys from
     * @param salt A string version of the salt; base64 encoded.
     * @return The XChaCha20 and AES keys.
     * @throws GeneralSecurityException
     */
    @JvmStatic
    @Throws(GeneralSecurityException::class)
    fun generateKeyFromPasswordArgon2(password:String,salt:String?):SecretKeys {
        return generateKeyFromPasswordArgon2(password,Base64.decode(salt,BASE64_FLAGS))
    }

    /**
     *  PBKDF2 key derivation algorithm
     *
     */

    enum class PbeAlgorithm {
        PBKDF2WithHmacSHA1, //Android API minVersion 1
        PBKDF2withHmacSHA1And8BIT, //Android API minVersion 19
        PBKDF2withHmacSHA224, //Android API minVersion 26
        PBKDF2WithHmacSHA256, //Android API minVersion 26
        PBKDF2WithHmacSHA384, //Android API minVersion 26
        PBKDF2WithHmacSHA512 //Android API minVersion 26
    }

    /**
     * A function that generates password-based XChaCha20 and AES keys.
     *
     * @param password The password to derive the keys from.
     * @param salt is unique salt
     * @param pbeIterationCount is iteration count of PBKDF2.
     * @param pbeAlgorithm is PBKDF2 key derivation algorithm.
     * @return The XChaCha20 and AES keys.
     * @throws GeneralSecurityException if AES is not implemented on this system,
     * or a suitable RNG is not available
     */
    @Throws(GeneralSecurityException::class)
    fun generateKeyFromPasswordPBKDF2(
        password:String,salt:ByteArray,pbeIterationCount:Int = PBE_ITERATION_COUNT,pbeAlgorithm:PbeAlgorithm = PBE_ALGORITHM
    ):SecretKeys {
        fixPrng() //Get enough random bytes for both the AES key and the HMAC key:
        if(pbeIterationCount<50000) throw GeneralSecurityException("too few PBKDF2 iterations (minimum is 50 000)")
        val keySpec:KeySpec = PBEKeySpec(
            password.toCharArray(),salt,pbeIterationCount,AES_KEY_LENGTH_BITS*2
        )
        val keyFactory = SecretKeyFactory.getInstance(pbeAlgorithm.toString())
        val keyBytes = keyFactory.generateSecret(keySpec).encoded

        // Split the random bytes into two parts:
        val confidentialityKeyBytes = copyOfRange(keyBytes,0,AES_KEY_LENGTH_BITS/8)
        val confidentialityKeyBytesGCM = copyOfRange(
            keyBytes,AES_KEY_LENGTH_BITS/88,2*AES_KEY_LENGTH_BITS/8
        )

        //Generate the XChaCha20 key
        val confidentialityKeyChaCha20:SecretKey = SecretKeySpec(confidentialityKeyBytes,CIPHER)

        //Generate the AES-GCM key
        val confidentialityKeyGCM:SecretKey = SecretKeySpec(confidentialityKeyBytesGCM,CIPHER)
        return SecretKeys(confidentialityKeyChaCha20,confidentialityKeyGCM)
    }

    /**
     * A function that generates password-based XChaCha20 and AES keys. See generateKeyFromPassword.
     * @param password The password to derive the XChaCha20 and AES keys from
     * @param salt A string version of the salt; base64 encoded.
     * @return The XChaCha20 and AES keys.
     * @throws GeneralSecurityException
     */
    @JvmStatic
    @Throws(GeneralSecurityException::class)
    fun generateKeyFromPasswordPBKDF2(password:String,salt:String?):SecretKeys {
        return generateKeyFromPasswordPBKDF2(password,Base64.decode(salt,BASE64_FLAGS))
    }

    /**
     * Generates a random salt.
     * @return The random salt suitable for generateKeyFromPassword.
     */
    @JvmStatic
    @Throws(GeneralSecurityException::class)
    fun generateSalt():ByteArray {
        return randomBytes(PBE_SALT_LENGTH_BITS)
    }

    /**
     * Converts the given salt into a base64 encoded string suitable for
     * storage.
     *
     * @param salt
     * @return a base 64 encoded salt string suitable to pass into generateKeyFromPassword.
     */
    @JvmStatic
    fun saltString(salt:ByteArray?):String {
        return Base64.encodeToString(salt,BASE64_FLAGS)
    }

    /**
     * Creates a random Initialization Vector (IV) of IV_LENGTH_BYTES.
     *
     * @return The byte array of this IV
     * @throws GeneralSecurityException if a suitable RNG is not available
     */
    @Throws(GeneralSecurityException::class)
    fun generateIv():ByteArray {
        return randomBytes(IV_LENGTH_BYTES)
    }

    @Throws(GeneralSecurityException::class)
    private fun randomBytes(length:Int):ByteArray {
        fixPrng()
        val random = SecureRandom()
        val b = ByteArray(length)
        random.nextBytes(b)
        return b
    }

    /*
     * -----------------------------------------------------------------
     * Encryption
     * -----------------------------------------------------------------
     */
    /**
     * Generates a random IV and encrypts this plain text with the given key.
     *
     * @param plaintext The text that will be encrypted, which
     * will be serialized with UTF-8
     * @param secretKeys The XChaCha20 and AES keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if UTF-8 is not supported in this system
     */
    @JvmStatic
    @JvmOverloads
    @Throws(UnsupportedEncodingException::class,GeneralSecurityException::class)
    fun encrypt(plaintext:String,secretKeys:SecretKeys,encoding:String? = "UTF-8"):CipherTextIvHeader {
        return encrypt(plaintext.toByteArray(charset(encoding!!)),secretKeys)
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key.
     *
     * @param plaintext The text that will be encrypted
     * @param secretKeys The combined XChaCha20 and AES-GCM keys with which to encrypt
     * @return a tuple of the IV, ciphertext, mac
     * @throws GeneralSecurityException if AES is not implemented on this system
     */
    @Throws(GeneralSecurityException::class)
    fun encrypt(plaintext:ByteArray,secretKeys:SecretKeys):CipherTextIvHeader {
        return initializeLibsodium {
            val key = secretKeys.confidentialityKeyChaCha20.toString().encodeToUByteArray()

            val secretStreamStateAndHeader = SecretStream.xChaCha20Poly1305InitPush(key)

            val byteCipherTextChaCha20 = SecretStream.xChaCha20Poly1305Push(
                secretStreamStateAndHeader.state,plaintext.toUByteArray(),ubyteArrayOf(),0U
            ).toByteArray()

            var iv = generateIv()
            val aesCipherForEncryptionGCM = Cipher.getInstance(CIPHER_TRANSFORMATION)
            aesCipherForEncryptionGCM.init(Cipher.ENCRYPT_MODE,secretKeys.confidentialityKeyAes,IvParameterSpec(iv))

            /*
                 * Now we get back the IV that will actually be used. Some Android
                 * versions do funny stuff w/ the IV, so this is to work around bugs:
                 */
            iv = aesCipherForEncryptionGCM.iv
            val byteCipherTextGCM = aesCipherForEncryptionGCM.doFinal(byteCipherTextChaCha20)
            CipherTextIvHeader(byteCipherTextGCM,iv,secretStreamStateAndHeader.header.asByteArray())
        }
    }

    /**
     * Generates a random IV and encrypts this plain text with the given key.
     *
     * @param inputStream inputstream that is going to be encrypted
     * @param outputStream outputstream, where the encrypted data is pushed
     * @param secretKeys The combined XChaCha20 and AES-GCM keys with which to encrypt
     * @param inputSize size of the input data in bytes
     * @param listener StreamLister progress listener
     * @param bufferSize Size of the buffer. NOTE: has to be the same when encrypting/decrypting.
     * @throws GeneralSecurityException if AES is not implemented on this system
     */
    @Throws(GeneralSecurityException::class)
    fun encrypt(inputStream:InputStream,outputStream:OutputStream,secretKeys:SecretKeys,inputSize:Long,
                listener:StreamListener,bufferSize:Int = BUFFER_SIZE) {
        return initializeLibsodium {
            try {
                val aesCipherForEncryptionGCM = Cipher.getInstance(CIPHER_TRANSFORMATION)
                var buffer = ByteArray(bufferSize)
                var bytesCopied:Long = 0
                val chaCha20Key = secretKeys.confidentialityKeyChaCha20.toString().encodeToUByteArray()
                var read = inputStream.read(buffer)
                while(read>=0) {
                    val secretStreamStateAndHeader = SecretStream.xChaCha20Poly1305InitPush(chaCha20Key)
                    val byteCipherTextChaCha20 = SecretStream.xChaCha20Poly1305Push(
                        secretStreamStateAndHeader.state,buffer.run {
                            if(read==BUFFER_SIZE) {
                                this
                            } else {
                                copyOfRange(0,read)
                            }
                        }.toUByteArray(),ubyteArrayOf(),0U
                    ).toByteArray()
                    val iv = generateIv()
                    aesCipherForEncryptionGCM.init(Cipher.ENCRYPT_MODE,secretKeys.confidentialityKeyAes,IvParameterSpec(iv))
                    val byteCipherTextGCM = aesCipherForEncryptionGCM.doFinal(byteCipherTextChaCha20)
                    outputStream.apply {
                        write(iv)
                        write(secretStreamStateAndHeader.header.toByteArray())
                        write(byteCipherTextGCM)
                    }
                    bytesCopied += read
                    listener.onProgress(read,bytesCopied,inputSize)
                    read = inputStream.read(buffer)
                }
                listener.onSuccess(bytesCopied.toString())
            } catch(e:IOException) {
                listener.onFailure("Cannot write outPutStream",e)
            } finally {
                outputStream.flush()
                outputStream.close()
                inputStream.close()
            }
        }
    }

    /**
     * Ensures that the PRNG is fixed. Should be used before generating any keys.
     * Will only run once, and every subsequent call should return immediately.
     */
    private fun fixPrng() {
        if(!prngFixed.get()) {
            synchronized(PrngFixes::class.java) {
                if(!prngFixed.get()) {
                    PrngFixes.apply()
                    prngFixed.set(true)
                }
            }
        }
    }/*
     * -----------------------------------------------------------------
     * Decryption
     * -----------------------------------------------------------------
     */

    /**
     * XChaCha20 and AES-GCM decrypt.
     *
     * @param civ The cipher text, IV, and mac
     * @param secretKeys The XChaCha20 and AES keys
     * @param encoding The string encoding to use to decode the bytes after decryption
     * @return A string derived from the decrypted bytes (not base64 encoded)
     * @throws GeneralSecurityException if AES is not implemented on this system
     * @throws UnsupportedEncodingException if the encoding is unsupported
     */
    @JvmStatic
    @JvmOverloads
    @Throws(UnsupportedEncodingException::class,GeneralSecurityException::class)
    fun decryptString(civ:CipherTextIvHeader,secretKeys:SecretKeys,encoding:String = "UTF-8"):String {
        return decrypt(civ,secretKeys).toString(Charset.forName(encoding))
    }

    /**
     * XChaCha20 and AES-GCM decrypt.
     *
     * @param civ the cipher text, AES iv, and ChaCha20 header
     * @param secretKeys the XChaCha20 and AES keys
     * @return The raw decrypted bytes
     * @throws GeneralSecurityException if  AES is not implemented
     */
    @Throws(GeneralSecurityException::class)
    fun decrypt(civ:CipherTextIvHeader,secretKeys:SecretKeys):ByteArray {
        var value:ByteArray? = null
        LibsodiumInitializer.initializeWithCallback {
            val aesCipherForDecryptionGCM = Cipher.getInstance(CIPHER_TRANSFORMATION)
            aesCipherForDecryptionGCM.init(
                Cipher.DECRYPT_MODE,secretKeys.confidentialityKeyAes,IvParameterSpec(civ.iv)
            )
            val cipherTextGCM = aesCipherForDecryptionGCM.doFinal(civ.cipherText)

            val key = secretKeys.confidentialityKeyChaCha20.toString().encodeToUByteArray()
            val secretStreamStateAndHeader = SecretStream.xChaCha20Poly1305InitPull(key,civ.header.toUByteArray())
            value = SecretStream.xChaCha20Poly1305Pull(
                secretStreamStateAndHeader.state,cipherTextGCM.toUByteArray(),ubyteArrayOf()
            ).decryptedData.toByteArray()
        }
        return value!!
    }

    /**
     * XChaCha20 and AES-GCM decrypt.
     *
     * @param inputStream inputstream that is going to be decrypted
     * @param outputStream outputstream, where the decrypted data is pushed
     * @param secretKeys The combined XChaCha20 and AES-GCM keys with which to decrypt
     * @param inputSize size of the input data in bytes
     * @param listener StreamLister progress listener
     * @param bufferSize Size of the buffer. NOTE: has to be the same when encrypting/decrypting.
     * @throws GeneralSecurityException if AES is not implemented on this system
     */
    @Throws(GeneralSecurityException::class)
    fun decrypt(inputStream:InputStream,outputStream:OutputStream,secretKeys:SecretKeys,inputSize:Long,listener:StreamListener,bufferSize:Int = BUFFER_SIZE) {
        return initializeLibsodium {
            try {
                val header = ByteArray(24)
                val aesCipherForDecryptionGCM = Cipher.getInstance(CIPHER_TRANSFORMATION)
                val chaCha2020key = secretKeys.confidentialityKeyChaCha20.toString().encodeToUByteArray()

                val buffer = ByteArray(bufferSize+24)
                var bytesCopied = 0L
                val iv = ByteArray(IV_LENGTH_BYTES)
                inputStream.read(iv)
                inputStream.read(header)
                var read = inputStream.read(buffer)
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
                    val secretStreamStateAndHeader = SecretStream.xChaCha20Poly1305InitPull(chaCha2020key,header.toUByteArray())
                    val block = SecretStream.xChaCha20Poly1305Pull(
                        secretStreamStateAndHeader.state,cipherTextGCM.toUByteArray(),ubyteArrayOf()
                    ).decryptedData.toByteArray()

                    outputStream.write(block)
                    bytesCopied += read
                    listener.onProgress(read,bytesCopied,inputSize)
                    inputStream.read(iv)
                    inputStream.read(header)
                    listener.onProgress(read,bytesCopied,inputSize)
                    read = inputStream.read(buffer)
                }
                listener.onSuccess(bytesCopied.toString())
            } catch(e:IOException) {
                listener.onFailure("Cannot write outPutStream",e)
            } finally {
                outputStream.flush()
                outputStream.close()
                inputStream.close()
            }
        }
    }

    /*
     * -----------------------------------------------------------------
     * Helper Code
     * -----------------------------------------------------------------
     */

    /**
     * Copy the elements from the start to the end
     *
     * @param from  the source
     * @param start the start index to copy
     * @param end   the end index to finish
     * @return the new buffer
     */
    private fun copyOfRange(from:ByteArray,start:Int,end:Int):ByteArray {
        val length = end-start
        val result = ByteArray(length)
        System.arraycopy(from,start,result,0,length)
        return result
    }

    /**
     * Holder class that has both the secret XChaCha20 key for encryption (confidentiality)
     * and the secret AES key for encryption (confidentiality).
     */
    class SecretKeys(confidentialityKeyIn:SecretKey?,confidentialityKeyInGCM:SecretKey?) {
        var confidentialityKeyChaCha20:SecretKey? = null
        var confidentialityKeyAes:SecretKey? = null

        /**
         * Construct the secret keys container.
         * @param confidentialityKeyChaCha20 The XChaCha20 key
         * @param confidentialityKeyAes The AES key
         */
        init {
            confidentialityKeyChaCha20 = confidentialityKeyIn
            confidentialityKeyAes = confidentialityKeyInGCM
        }

        /**
         * Encodes the two keys as a string
         * @return base64(confidentialityKeyChaCha20):base64(confidentialityKeyAes)
         */
        override fun toString():String {
            return (Base64.encodeToString(confidentialityKeyChaCha20!!.encoded,BASE64_FLAGS)+":"+Base64.encodeToString(
                confidentialityKeyAes!!.encoded,BASE64_FLAGS
            ))
        }

        override fun hashCode():Int {
            val prime = 31
            var result = 1
            result = prime*result+confidentialityKeyChaCha20.hashCode()
            result = prime*result+confidentialityKeyAes.hashCode()
            return result
        }

        override fun equals(obj:Any?):Boolean {
            if(this===obj) return true
            if(obj==null) return false
            if(javaClass!=obj.javaClass) return false
            val other = obj as SecretKeys
            if(confidentialityKeyAes!=other.confidentialityKeyAes) return false
            if(confidentialityKeyChaCha20!=other.confidentialityKeyChaCha20) false
            return true
        }
    }

    /**
     * Holder class that allows us to bundle ciphertext and IV together.
     */
    class CipherTextIvHeader {
        val cipherText:ByteArray
        val iv:ByteArray // AES-GCM IV
        val header:ByteArray // XChaCha20 header

        /**
         * Construct a new bundle of ciphertext and IV.
         * @param c The ciphertext
         * @param i The IV of AES
         * @param h The header of XChaCha20
         */
        constructor(c:ByteArray,i:ByteArray,h:ByteArray) {
            cipherText = ByteArray(c.size)
            System.arraycopy(c,0,cipherText,0,c.size)
            iv = ByteArray(i.size)
            System.arraycopy(i,0,iv,0,i.size)
            header = ByteArray(h.size)
            System.arraycopy(h,0,header,0,h.size)
        }

        /**
         * Constructs a new bundle of ciphertext and IV from a string of the
         * format `base64(iv):base64(ciphertext)`.
         *
         * @param base64CiphertextIVHeaderText A string of the format
         * `ciphertext:iv:header` The ciphertext, IV and header must each
         * be base64-encoded.
         */
        constructor(base64CiphertextIVHeaderText:String) {
            val civArray = base64CiphertextIVHeaderText.split(":").toTypedArray()
            require(civArray.size==3) {"Cannot parse ciphertext:iv:header"}
            cipherText = Base64.decode(civArray[0],BASE64_FLAGS)
            iv = Base64.decode(civArray[1],BASE64_FLAGS)
            header = Base64.decode(civArray[2],BASE64_FLAGS)
        }

        /**
         * Encodes this ciphertext, IV, header as a string.
         *
         * @return base64(ciphertext) : base64(iv) : base64(header)
         */
        override fun toString():String {
            val cipherTextString = Base64.encodeToString(cipherText,BASE64_FLAGS)
            val ivString = Base64.encodeToString(iv,BASE64_FLAGS)
            val headerString = Base64.encodeToString(header,BASE64_FLAGS)
            return String.format("$cipherTextString:$ivString:$headerString")
        }

        override fun hashCode():Int {
            val prime = 31
            var result = 1
            result = prime*result+Arrays.hashCode(cipherText)
            result = prime*result+Arrays.hashCode(iv)
            result = prime*result+Arrays.hashCode(header)
            return result
        }

        override fun equals(obj:Any?):Boolean {
            if(this===obj) return true
            if(obj==null) return false
            if(javaClass!=obj.javaClass) return false
            val other = obj as CipherTextIvHeader
            if(!Arrays.equals(cipherText,other.cipherText)) return false
            if(!Arrays.equals(iv,other.iv)) return false
            if(!Arrays.equals(header,other.header)) return false
            return true
        }
    }

    /**
     * Fixes for the RNG as per
     * http://android-developers.blogspot.com/2013/08/some-securerandom-thoughts.html
     *
     * This software is provided 'as-is', without any express or implied
     * warranty. In no event will Google be held liable for any damages arising
     * from the use of this software.
     *
     * Permission is granted to anyone to use this software for any purpose,
     * including commercial applications, and to alter it and redistribute it
     * freely, as long as the origin is not misrepresented.
     *
     * Fixes for the output of the default PRNG having low entropy.
     *
     * The fixes need to be applied via [.apply] before any use of Java
     * Cryptography Architecture primitives. A good place to invoke them is in
     * the application's `onCreate`.
     */
    object PrngFixes {
        private const val VERSION_CODE_JELLY_BEAN = 16
        private const val VERSION_CODE_JELLY_BEAN_MR2 = 18
        private val BUILD_FINGERPRINT_AND_DEVICE_SERIAL = buildFingerprintAndDeviceSerial

        /**
         * Applies all fixes.
         *
         * @throws SecurityException if a fix is needed but could not be
         * applied.
         */
        fun apply() {
            applyOpenSSLFix()
            installLinuxPRNGSecureRandom()
        }

        /**
         * Applies the fix for OpenSSL PRNG having low entropy. Does nothing if
         * the fix is not needed.
         *
         * @throws SecurityException if the fix is needed but could not be
         * applied.
         */
        @Throws(SecurityException::class)
        private fun applyOpenSSLFix() {
            if(Build.VERSION.SDK_INT<VERSION_CODE_JELLY_BEAN || Build.VERSION.SDK_INT>VERSION_CODE_JELLY_BEAN_MR2) { // No need to apply the fix
                return
            }
            try { // Mix in the device- and invocation-specific seed.
                Class.forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto").getMethod("RAND_seed",ByteArray::class.java)
                    .invoke(null,generateSeed())

                // Mix output of Linux PRNG into OpenSSL's PRNG
                val bytesRead = Class.forName("org.apache.harmony.xnet.provider.jsse.NativeCrypto")
                    .getMethod("RAND_load_file",String::class.java,Long::class.javaPrimitiveType).invoke(null,"/dev/urandom",1024) as Int
                if(bytesRead!=1024) {
                    throw IOException(
                        "Unexpected number of bytes read from Linux PRNG: "+bytesRead
                    )
                }
            } catch(e:Exception) {
                if(ALLOW_BROKEN_PRNG) {
                    Log.w(PrngFixes::class.java.simpleName,"Failed to seed OpenSSL PRNG",e)
                } else {
                    throw SecurityException("Failed to seed OpenSSL PRNG",e)
                }
            }
        }

        /**
         * Installs a Linux PRNG-backed `SecureRandom` implementation as
         * the default. Does nothing if the implementation is already the
         * default or if there is not need to install the implementation.
         *
         * @throws SecurityException if the fix is needed but could not be
         * applied.
         */
        @Throws(SecurityException::class)
        private fun installLinuxPRNGSecureRandom() {
            if(Build.VERSION.SDK_INT>VERSION_CODE_JELLY_BEAN_MR2) { // No need to apply the fix
                return
            }

            // Install a Linux PRNG-based SecureRandom implementation as the
            // default, if not yet installed.
            val secureRandomProviders = Security.getProviders("SecureRandom.SHA1PRNG")

            // Insert and check the provider atomically.
            // The official Android Java libraries use synchronized methods for
            // insertProviderAt, etc., so synchronizing on the class should
            // make things more stable, and prevent race conditions with other
            // versions of this code.
            synchronized(Security::class.java) {
                if(secureRandomProviders==null || secureRandomProviders.size<1 || secureRandomProviders[0].javaClass.simpleName!="LinuxPRNGSecureRandomProvider") {
                    Security.insertProviderAt(LinuxPRNGSecureRandomProvider(),1)
                }

                // Assert that new SecureRandom() and
                // SecureRandom.getInstance("SHA1PRNG") return a SecureRandom backed
                // by the Linux PRNG-based SecureRandom implementation.
                val rng1 = SecureRandom()
                if(rng1.provider.javaClass.simpleName!="LinuxPRNGSecureRandomProvider") {
                    if(ALLOW_BROKEN_PRNG) {
                        Log.w(
                            PrngFixes::class.java.simpleName,"new SecureRandom() backed by wrong Provider: "+rng1.provider.javaClass
                        )
                        return
                    } else {
                        throw SecurityException(
                            "new SecureRandom() backed by wrong Provider: "+rng1.provider.javaClass
                        )
                    }
                }
                var rng2:SecureRandom? = null
                try {
                    rng2 = SecureRandom.getInstance("SHA1PRNG")
                } catch(e:NoSuchAlgorithmException) {
                    if(ALLOW_BROKEN_PRNG) {
                        Log.w(PrngFixes::class.java.simpleName,"SHA1PRNG not available",e)
                        return
                    } else {
                        SecurityException("SHA1PRNG not available",e)
                    }
                }
                if(rng2!!.provider.javaClass.simpleName!="LinuxPRNGSecureRandomProvider") {
                    if(ALLOW_BROKEN_PRNG) {
                        Log.w(
                            PrngFixes::class.java.simpleName,
                            "SecureRandom.getInstance(\"SHA1PRNG\") backed by wrong"+" Provider: "+rng2.provider.javaClass
                        )
                        return
                    } else {
                        throw SecurityException(
                            "SecureRandom.getInstance(\"SHA1PRNG\") backed by wrong"+" Provider: "+rng2.provider.javaClass
                        )
                    }
                }
            }
        }

        /**
         * Generates a device- and invocation-specific seed to be mixed into the
         * Linux PRNG.
         */
        private fun generateSeed():ByteArray {
            return try {
                val seedBuffer = ByteArrayOutputStream()
                val seedBufferOut = DataOutputStream(seedBuffer)
                seedBufferOut.writeLong(System.currentTimeMillis())
                seedBufferOut.writeLong(System.nanoTime())
                seedBufferOut.writeInt(Process.myPid())
                seedBufferOut.writeInt(Process.myUid())
                seedBufferOut.write(BUILD_FINGERPRINT_AND_DEVICE_SERIAL)
                seedBufferOut.close()
                seedBuffer.toByteArray()
            } catch(e:IOException) {
                throw SecurityException("Failed to generate seed",e)
            }
        } // We're using the Reflection API because Build.SERIAL is only // available since API Level 9 (Gingerbread, Android 2.3).

        /**
         * Gets the hardware serial number of this device.
         *
         * @return serial number or `null` if not available.
         */
        private val deviceSerialNumber:String?
            private get() = // We're using the Reflection API because Build.SERIAL is only
                // available since API Level 9 (Gingerbread, Android 2.3).
                try {
                    Build::class.java.getField("SERIAL")[null] as String
                } catch(ignored:Exception) {
                    null
                }
        private val buildFingerprintAndDeviceSerial:ByteArray
            private get() {
                val result = StringBuilder()
                val fingerprint = Build.FINGERPRINT
                if(fingerprint!=null) {
                    result.append(fingerprint)
                }
                val serial = deviceSerialNumber
                if(serial!=null) {
                    result.append(serial)
                }
                return try {
                    result.toString().toByteArray(charset("UTF-8"))
                } catch(e:UnsupportedEncodingException) {
                    throw RuntimeException("UTF-8 encoding not supported")
                }
            }

        /**
         * `Provider` of `SecureRandom` engines which pass through
         * all requests to the Linux PRNG.
         */
        private class LinuxPRNGSecureRandomProvider:Provider(
            "LinuxPRNG",1.0,"A Linux-specific random number provider that uses"+" /dev/urandom"
        ) {
            init { // Although /dev/urandom is not a SHA-1 PRNG, some apps
                // explicitly request a SHA1PRNG SecureRandom and we thus need
                // to prevent them from getting the default implementation whose
                // output may have low entropy.
                put("SecureRandom.SHA1PRNG",LinuxPRNGSecureRandom::class.java.name)
                put("SecureRandom.SHA1PRNG ImplementedIn","Software")
            }
        }

        /**
         * [SecureRandomSpi] which passes all requests to the Linux PRNG (
         * `/dev/urandom`).
         */
        class LinuxPRNGSecureRandom:SecureRandomSpi() {
            /**
             * Whether this engine instance has been seeded. This is needed
             * because each instance needs to seed itself if the client does not
             * explicitly seed it.
             */
            private var mSeeded = false
            override fun engineSetSeed(bytes:ByteArray) {
                try {
                    var out:OutputStream?
                    synchronized(sLock) {out = urandomOutputStream}
                    out!!.write(bytes)
                    out!!.flush()
                } catch(e:IOException) { // On a small fraction of devices /dev/urandom is not
                    // writable Log and ignore.
                    Log.w(
                        PrngFixes::class.java.simpleName,"Failed to mix seed into "+URANDOM_FILE
                    )
                } finally {
                    mSeeded = true
                }
            }

            override fun engineNextBytes(bytes:ByteArray) {
                if(!mSeeded) { // Mix in the device- and invocation-specific seed.
                    engineSetSeed(generateSeed())
                }
                try {
                    var `in`:DataInputStream?
                    synchronized(sLock) {`in` = urandomInputStream}
                    synchronized(`in`!!) {`in`!!.readFully(bytes)}
                } catch(e:IOException) {
                    throw SecurityException("Failed to read from "+URANDOM_FILE,e)
                }
            }

            override fun engineGenerateSeed(size:Int):ByteArray {
                val seed = ByteArray(size)
                engineNextBytes(seed)
                return seed
            }

            // NOTE: Consider inserting a BufferedInputStream
            // between DataInputStream and FileInputStream if you need
            // higher PRNG output performance and can live with future PRNG
            // output being pulled into this process prematurely.
            private val urandomInputStream:DataInputStream?
                private get() {
                    synchronized(sLock) {
                        if(sUrandomIn==null) { // NOTE: Consider inserting a BufferedInputStream
                            // between DataInputStream and FileInputStream if you need
                            // higher PRNG output performance and can live with future PRNG
                            // output being pulled into this process prematurely.
                            try {
                                sUrandomIn = DataInputStream(FileInputStream(URANDOM_FILE))
                            } catch(e:IOException) {
                                throw SecurityException(
                                    "Failed to open "+URANDOM_FILE+" for reading",e
                                )
                            }
                        }
                        return sUrandomIn
                    }
                }

            @get:Throws(IOException::class)
            private val urandomOutputStream:OutputStream?
                private get() {
                    synchronized(sLock) {
                        if(sUrandomOut==null) {
                            sUrandomOut = FileOutputStream(URANDOM_FILE)
                        }
                        return sUrandomOut
                    }
                }

            companion object {
                /*
                     * IMPLEMENTATION NOTE: Requests to generate bytes and to mix in a
                     * seed are passed through to the Linux PRNG (/dev/urandom).
                     * Instances of this class seed themselves by mixing in the current
                     * time, PID, UID, build fingerprint, and hardware serial number
                     * (where available) into Linux PRNG.
                     *
                     * Concurrency: Read requests to the underlying Linux PRNG are
                     * serialized (on sLock) to ensure that multiple threads do not get
                     * duplicated PRNG output.
                     */
                private val URANDOM_FILE = File("/dev/urandom")
                private val sLock = Any()

                /**
                 * Input stream for reading from Linux PRNG or `null` if not
                 * yet opened.
                 *
                 * @GuardedBy("sLock")
                 */
                private var sUrandomIn:DataInputStream? = null

                /**
                 * Output stream for writing to Linux PRNG or `null` if not
                 * yet opened.
                 *
                 * @GuardedBy("sLock")
                 */
                private var sUrandomOut:OutputStream? = null
            }
        }
    }
}