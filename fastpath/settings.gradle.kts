pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

@Suppress("UnstableApiUsage")
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "aegis-fastpath"

// core       the engine: semantic observations in, events + intervention step out. No text.
// transcript text layer: transcript updates, normaliser, lexicon extractor
// privacy  on-device PII filter: the only producer of anything text-shaped that may leave
// uplink   journal + transport; accepts EgressPayload only
// replay   JVM harness: scripted calls through the whole fast path, no phone or model needed
include(":core")
include(":transcript")
include(":privacy")
include(":uplink")
include(":replay")
