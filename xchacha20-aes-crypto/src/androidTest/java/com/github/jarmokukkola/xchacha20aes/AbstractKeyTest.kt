package com.github.jarmokukkola.xchacha20aes

import org.junit.Assert
import java.util.*

abstract class AbstractKeyTest {
    protected fun getTime() = GregorianCalendar().timeInMillis

    protected fun testDuration(time:Long) {
        val duration = GregorianCalendar().timeInMillis-time
        Assert.assertTrue(duration<5000)
        Assert.assertTrue(duration>50)
    }
}