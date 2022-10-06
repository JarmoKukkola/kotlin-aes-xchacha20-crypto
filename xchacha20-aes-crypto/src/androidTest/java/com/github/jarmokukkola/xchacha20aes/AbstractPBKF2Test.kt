package com.github.jarmokukkola.xchacha20aes

import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.PBE_ITERATION_COUNT
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.generateKeyFromPasswordPBKDF2
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM.generateSalt
import org.junit.Assert
import org.junit.Test
import java.util.*

abstract class AbstractPBKF2Test {
    private fun generatePassword(iterations:Int = PBE_ITERATION_COUNT) {
        val time = GregorianCalendar().timeInMillis
        generateKeyFromPasswordPBKDF2("gfdfgdfgfdg",generateSalt(),iterations,pbeAlgorithm)
        Assert.assertTrue(GregorianCalendar().timeInMillis-time<5000)
    }

    abstract val pbeAlgorithm:XChaCha20AesGCM.PbeAlgorithm

    @Test
    fun keyGenerationTime50000() {
        generatePassword(50000)
    }

    @Test
    fun keyGenerationTime100000() {
        generatePassword(100000)
    }

    @Test
    fun keyGenerationTime200000() {
        generatePassword(200000)
    }

    @Test
    fun keyGenerationTime310000() {
        generatePassword()
    }

    @Test
    fun keyGenerationTime400000() {
        generatePassword(400000)
    }

    @Test
    fun keyGenerationTime500000() {
        generatePassword(500000)
    }

    @Test
    fun keyGenerationTime600000() {
        generatePassword(600000)
    }

    @Test
    fun keyGenerationTime700000() {
        generatePassword(700000)
    }

    @Test
    fun keyGenerationTime800000() {
        generatePassword(800000)
    }
}