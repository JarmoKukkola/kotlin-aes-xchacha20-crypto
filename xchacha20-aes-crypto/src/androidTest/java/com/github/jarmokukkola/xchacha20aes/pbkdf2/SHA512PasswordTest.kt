package com.github.jarmokukkola.xchacha20aes.pbkdf2

import com.github.jarmokukkola.xchacha20aes.AbstractPBKF2Test
import com.github.jarmokukkola.xchacha20aes.XChaCha20AesGCM

class SHA512PasswordTest:AbstractPBKF2Test() {
    override val pbeAlgorithm = XChaCha20AesGCM.PbeAlgorithm.PBKDF2WithHmacSHA512
}