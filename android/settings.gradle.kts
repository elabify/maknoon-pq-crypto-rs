// Standalone Gradle project for the Maknoon PqCryptoCore Android library.
// Builds an .aar containing the Rust JNI libs (libpq_crypto_core.so per
// ABI), the UniFFI-generated Kotlin glue, and metadata.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "pq-crypto-core"
include(":library")
