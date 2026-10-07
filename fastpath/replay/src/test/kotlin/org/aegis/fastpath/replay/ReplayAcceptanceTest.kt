package org.aegis.fastpath.replay

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReplayAcceptanceTest {
    private fun inputs(dir: String, ext: String) =
        File(System.getProperty("aegis.root", ".."), dir).listFiles { f -> f.extension == ext }.orEmpty().sortedBy { it.name }

    @Test
    fun `every call script meets its expectation with zero leakage`() {
        val scripts = inputs("scripts", "txt")
        assertTrue(scripts.isNotEmpty(), "no scripts found")
        val runner = ReplayRunner(File("build/replay-test/text"), out = null)
        val failures = scripts.map { runner.run(CallScript.parse(it)) }.filter { !it.passed }
        assertTrue(failures.isEmpty(), failures.joinToString("\n") {
            "${it.name}: step ${it.finalStep} expected ${it.expectedStep}, leaks ${it.canaryLeaks}, blocked ${it.blocked}"
        })
    }

    /**
     * The engine is extractor-agnostic: replaying the observations the lexicon produced, with no
     * text anywhere, must give the same decisions at the same moments.
     */
    @Test
    fun `the engine decides identically from recorded observations alone`() {
        val text = ReplayRunner(File("build/replay-test/text2"), out = null)
        val obs = ReplayRunner(File("build/replay-test/obs"), out = null)
        for (script in inputs("scripts", "txt")) {
            val a = text.run(CallScript.parse(script))
            val b = obs.runObservations(a.observationsFile)
            assertEquals(a.finalStep, b.finalStep, script.name)
            assertEquals(a.stepAtMs, b.stepAtMs, script.name)
            assertEquals(a.eventsSent, b.eventsSent, script.name)
        }
    }

    @Test
    fun `observation files from external extractors meet their expectations`() {
        val files = inputs("observations", "jsonl")
        assertTrue(files.isNotEmpty(), "no observation files found")
        val runner = ReplayRunner(File("build/replay-test/external"), out = null)
        val failures = files.map { runner.runObservations(it) }.filter { !it.passed }
        assertTrue(failures.isEmpty(), failures.joinToString("\n") { "${it.name}: step ${it.finalStep} expected ${it.expectedStep}" })
    }
}
