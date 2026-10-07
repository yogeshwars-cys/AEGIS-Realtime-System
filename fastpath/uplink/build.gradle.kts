plugins {
    id("org.jetbrains.kotlin.jvm")
}

// The uplink sees core (events) and privacy (EgressPayload). It never depends on whatever
// produces raw transcripts on the phone, and its only entry point takes an EgressPayload.
dependencies {
    api(project(":privacy"))
}
