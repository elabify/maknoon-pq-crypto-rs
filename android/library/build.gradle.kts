plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.elabify.pqcrypto"
    compileSdk = 34

    defaultConfig {
        // Android 8.0. The Maknoon app floors at API 33; this lib stays
        // at 26 so it can be reused as widely as the ledger-*-rs cores.
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")

        // cargo-ndk drops the .so files into src/main/jniLibs/<abi>/;
        // AGP packages them automatically (no ndk{} block needed).
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // UniFFI-generated Kotlin glue loads the native lib via JNA.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    // UniFFI async-callback support (kept for parity with the cores even
    // though pq-crypto-core has no async fns today).
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
