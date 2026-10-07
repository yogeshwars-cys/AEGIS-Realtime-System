plugins {
    id("org.jetbrains.kotlin.jvm")
    application
}

dependencies {
    implementation(project(":uplink"))
}

application {
    mainClass.set("org.aegis.fastpath.replay.ReplayMainKt")
}

tasks.named<JavaExec>("run") {
    // Relative script paths should mean what they say from fastpath/, not replay/.
    workingDir = rootProject.projectDir
}
