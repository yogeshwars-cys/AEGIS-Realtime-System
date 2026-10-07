plugins {
    id("org.jetbrains.kotlin.jvm")
}

// The text layer: transcript updates, normalisation, and the lexicon extractor. Turns text into
// SemanticObservations for core. core never depends on this module.
dependencies {
    api(project(":core"))
}
