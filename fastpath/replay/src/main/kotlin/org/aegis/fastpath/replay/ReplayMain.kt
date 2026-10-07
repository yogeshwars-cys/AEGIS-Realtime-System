package org.aegis.fastpath.replay

import java.io.File
import kotlin.system.exitProcess

private val INPUTS = setOf("txt", "jsonl")

/**
 * `./gradlew :replay:run` replays every call script in `scripts/` (text through the lexicon
 * extractor) and every observations file in `observations/` (straight into the engine).
 * `./gradlew :replay:run --args="scripts/scam_digital_arrest.txt --partial-lag 250 --endpoint 500"`
 *
 * Exit code 1 if any script misses its expected step or leaks a canary, so it doubles as an
 * acceptance gate in CI.
 */
fun main(args: Array<String>) {
    var partialLag = 300L
    var endpoint = 600L
    var quiet = false
    val paths = mutableListOf<String>()
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--partial-lag" -> partialLag = args[++i].toLong()
            "--endpoint" -> endpoint = args[++i].toLong()
            "--quiet" -> quiet = true
            else -> paths += args[i]
        }
        i++
    }
    if (paths.isEmpty()) paths += listOf("scripts", "observations")

    val files = paths.flatMap { p ->
        val f = File(p)
        if (f.isDirectory) f.listFiles { x -> x.extension in INPUTS }.orEmpty().sortedBy { it.name } else listOf(f)
    }
    require(files.isNotEmpty()) { "no scripts found in $paths" }

    val runner = ReplayRunner(File("build/replay"), SimulatedAsr(partialLag, endpoint), if (quiet) null else System.out)
    val results = files.map { if (it.extension == "jsonl") runner.runObservations(it) else runner.run(CallScript.parse(it)) }

    println()
    println("== summary (simulated ASR: partial lag ${partialLag} ms, endpoint ${endpoint} ms)")
    for (r in results) {
        val pause = r.stepAtMs[org.aegis.fastpath.risk.FrictionStep.PAUSE]?.let { "pause at %.1fs".format(it / 1000.0) } ?: ""
        println(String.format("  %s %-34s %-7s %-16s leaks=%d", if (r.passed) "ok  " else "FAIL", r.name, r.finalStep, pause, r.canaryLeaks.size + r.blocked.size))
    }
    if (results.any { !it.passed }) exitProcess(1)
}
