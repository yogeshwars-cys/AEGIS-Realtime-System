plugins {
    id("org.jetbrains.kotlin.jvm")
}

// Pure JVM, like core. javax.crypto (HMAC) exists on Android too.
dependencies {
    api(project(":transcript"))
}
