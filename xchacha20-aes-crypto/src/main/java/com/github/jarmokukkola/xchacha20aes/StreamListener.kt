package com.github.jarmokukkola.xchacha20aes

interface StreamListener {
    fun onProgress(newBytes:Int,bytesProcessed:Long,totalBytes:Long) {}
    fun <T> onSuccess(result:T)
    fun onFailure(message:String,e:Exception)
}