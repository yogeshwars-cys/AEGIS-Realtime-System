plugins {
    id("org.jetbrains.kotlin.jvm")
}

// core is pure JVM: no Android dependency, no third-party runtime dependency.
// Its tests run on any JDK 21 with no Android SDK. Keep it that way.
