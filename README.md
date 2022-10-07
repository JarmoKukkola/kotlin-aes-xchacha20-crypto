kotlin-aes-xchacha20-crypto
===============

This AES/XChaCha20 library is very simple and works only on Android. It is used for encrypting &amp; decrypting strings, byte arrays or inputstreams.

This library is based on https://github.com/tozny/java-aes-crypto.

This version of the library was modified by Dr. Jarmo Kukkola, aiming to increase flexibility and security.

# List of modifications compared to Tonzy's implementation

* Migrated from Java to Kotlin.
* Made it possible to change PBKDF2 iteration count and algorithm type. Algorithm types can be seen in https://developer.android.com/guide/topics/security/cryptography under SecretKeyFactory - PBKDF2...
* Added dependency https://github.com/ionspin/kotlin-multiplatform-libsodium (Apache 2.0), which depends on https://github.com/jedisct1/libsodium (ISC License).
* Added option to generate key from password using Argon2.
* Increased default PBKDF2 iteration count from 10000 to 100000.
* Instead of AES-128-CBC encryption, implemented double encryption, once with AES-256-GCM and another time with XChaCha20. Each are using unique key. The purpose is to reduce probability of successful attacks.
* Increased minimum android API version to 21.
* Added more robust tests, including measurements of key derivation time with PBKDF2 and Argon2.

# Features

Here are the features of this class. We believe that these properties are consistent with what a lot of people are looking for when encrypting Strings in Android.

* *Works for strings*: It should encrypt arbitrary strings, byte arrays or inputstreams. This means it needs to effectively handle multiple blocks (CBC) and partial blocks (padding). It consistently serializes and deserializes ciphertext, IVs, and key material using base64 to make it easy to store.
* *Algorithm & Mode*: Double enryption: XChaCha20 + Poly1305 and then the result is encrypted again with AES 256, GCM, and No padding. Each type encryption of encryption uses their unique key.
* *IV Handling*: We securely generate a random IV before each encryption and provide a simple class to keep the IV and ciphertext together so they're easy to keep track of and store. We set the IV and then request it back from the Cipher class for compatibility across various Android versions.
* *Key generation*: Random key generation with the updated generation code recommended for Android. If you want password-based keys, we provide functions to salt and generate them using PBKDF2, Argon2_ID or them combined.
* *Older Phones*: It's designed for backward compatibility with older phones, including ciphers that are available for most versions of Android as well as entropy fixes for old Android bugs.


# How to include in project?

## Android Library project

The library is in Android library project format so you can clone this project
and add as a library module/project.

## Maven Dependency

We've also published the library AAR file via Jitpack for simple
gradle dependency management:

Add the Jitpack repository to your root build.gradle:

```groovy
allprojects {
  repositories {
    ...
    maven { url 'https://jitpack.io' }
  }
}
```

Add the dependency to your project's build.gradle:

```groovy
dependencies {
  implementation 'com.github.JarmoKukkola:kotlin-aes-xchacha20-crypto:*.*.*' // where *.*.* is the latest library version
}
```

# Examples

## Generate new key

```java
  XChaCha20AesGCM.SecretKeys keys = XChaCha20AesGCM.generateKey();
```

## Generate a key from a password or passphrase
```java
  EXAMPLE_PASSWORD = // Get password from user input
  String salt = saltString(generateSalt());
  // You can store the salt, it's not secret. Don't store the key. Derive from password every time
  Log.i(TAG, "Salt: " + salt);
  key = generateKeyFromPassword(EXAMPLE_PASSWORD, salt);
  // alternatively generateKeyFromPasswordArgon2(EXAMPLE_PASSWORD, salt); 
  // alternatively generateKeyFromPasswordPBKDF2(EXAMPLE_PASSWORD, salt); 
```

## Encrypt

```java
   XChaCha20AesGCM.CipherTextIvHeader cipherTextIvHeader = XChaCha20AesGCM.encrypt("some test", keys);
   //store or send to server
   String ciphertextString = cipherTextIvHeader.toString();
```

## Decrypt

```java
  //Use the constructor to re-create the CipherTextIvMac class from the string:
  CipherTextIvHeader cipherTextIvHeader = new CipherTextIvHeader (cipherTextString);
  String plainText = XChaCha20AesGCM.decryptString(cipherTextIvHeader, keys);
```

## Storing Keys

Once you've generated a random key, you naturally might want to store it. This
may work for some use cases, but please be aware that if you store the key in
the same place that you store the encrypted data, your solution is not
cryptographically sound since the attacker can just get both the key and the
encrypted text. Instead, you should use either the [Keystore
infrastructure](http://developer.android.com/training/articles/keystore.html)
or consider generating the key from a passphrase and using that to encrypt the
user data.

If despite the above you still want to store the key, you can convert the keys
to a string using the included functions and store them in preferences or
SQLite.

Note that if you hard-code keys or passphrases, or generate them from a static
value, you will likely get an [error message from the Android security scanner](https://support.google.com/faqs/answer/9450925).

# License

The included MIT license is compatible with open source or commercial products.

