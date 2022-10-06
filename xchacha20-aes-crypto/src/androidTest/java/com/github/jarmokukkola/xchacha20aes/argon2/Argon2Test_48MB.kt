package com.github.jarmokukkola.xchacha20aes.argon2

import com.github.jarmokukkola.xchacha20aes.AbstractArgon2Test

class Argon2Test_48MB:AbstractArgon2Test() {
    override val maxMemory:Int = 48*1024*1024
}