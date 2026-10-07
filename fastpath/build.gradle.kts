plugins {
    // Applied per-module. Versions chosen so the Android app module can join this build
    // later without a toolchain change.
    id("org.jetbrains.kotlin.jvm") version "1.9.24" apply false
}

subprojects {
    plugins.withId("org.jetbrains.kotlin.jvm") {
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
            jvmToolchain(21)
        }
        dependencies {
            "testImplementation"(kotlin("test"))
            "testImplementation"("org.junit.jupiter:junit-jupiter:5.10.2")
            "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
        }
        tasks.withType<Test>().configureEach {
            useJUnitPlatform()
            testLogging {
                events("failed")
                exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            }
        }
    }
}
