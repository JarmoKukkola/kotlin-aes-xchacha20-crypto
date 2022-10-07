package com.github.jarmokukkola.xchacha20aes

import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.generateKeyFromPasswordArgon2
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.generateSalt
import com.ionspin.kotlin.crypto.pwhash.crypto_pwhash_OPSLIMIT_INTERACTIVE
import com.ionspin.kotlin.crypto.pwhash.crypto_pwhash_OPSLIMIT_MODERATE
import com.ionspin.kotlin.crypto.pwhash.crypto_pwhash_OPSLIMIT_SENSITIVE
import org.junit.Test

abstract class AbstractArgon2Test:AbstractKeyTest() {
    private fun generatePassword(opsLimit:ULong = crypto_pwhash_OPSLIMIT_SENSITIVE) {
        val time = getTime()
        generateKeyFromPasswordArgon2("gfdfgdfgfdg",generateSalt(),opsLimit,maxMemory)
        testDuration(time)
    }

    abstract val maxMemory:Int

    @Test
    fun keyGenerationTime_1024UL() {
        generatePassword(1024UL)
    }

    @Test
    fun keyGenerationTime_512UL() {
        generatePassword(512UL)
    }

    @Test
    fun keyGenerationTime_256UL() {
        generatePassword(256UL)
    }

    @Test
    fun keyGenerationTime_128UL() {
        generatePassword(128UL)
    }

    @Test
    fun keyGenerationTime_64UL() {
        generatePassword(64UL)
    }

    @Test
    fun keyGenerationTime_32UL() {
        generatePassword(32UL)
    }

    @Test
    fun keyGenerationTime_16UL() {
        generatePassword(16UL)
    }

    @Test
    fun keyGenerationTime_crypto_pwhash_OPSLIMIT_SENSITIVE() {
        generatePassword(crypto_pwhash_OPSLIMIT_SENSITIVE)
    }

    @Test
    fun keyGenerationTime_crypto_pwhash_OPSLIMIT_MODERATE() {
        generatePassword(crypto_pwhash_OPSLIMIT_MODERATE)
    }

    @Test
    fun keyGenerationTime_crypto_pwhash_OPSLIMIT_INTERACTIVE() {
        generatePassword(crypto_pwhash_OPSLIMIT_INTERACTIVE.toULong())
    }

}