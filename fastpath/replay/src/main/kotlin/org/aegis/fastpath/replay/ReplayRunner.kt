package org.aegis.fastpath.replay

import org.aegis.fastpath.engine.FastPathEngine
import org.aegis.fastpath.event.Evidence
import org.aegis.fastpath.event.SemanticEvent
import org.aegis.fastpath.observation.ObservationCodec
import org.aegis.fastpath.observation.SegmentObservation
import org.aegis.fastpath.observation.SemanticExtractor
import org.aegis.fastpath.prior.CallerPrior
import org.aegis.fastpath.privacy.EgressAuditor
import org.aegis.fastpath.privacy.EventUpdate
import org.aegis.fastpath.privacy.PiiType
import org.aegis.fastpath.privacy.PrivacyFilter
import org.aegis.fastpath.privacy.RedactedSegment
import org.aegis.fastpath.risk.FrictionStep
import org.aegis.fastpath.transcript.LexiconExtractor
import org.aegis.fastpath.transcript.ScamLexicon
import org.aegis.fastpath.transcript.TextNormalizer
import org.aegis.fastpath.transcript.TranscriptUpdate
import org.aegis.fastpath.uplink.EgressJournal
import org.aegis.fastpath.uplink.JsonlFileTransport
import org.aegis.fastpath.uplink.Uplink
import org.aegis.fastpath.util.Json
import org.aegis.fastpath.util.JsonReader
import java.io.File
import java.io.PrintStream

data class ReplayResult(
    val name: String,
    val title: String,
    val finalStep: FrictionStep,
    val expectedStep: FrictionStep?,
    /** Call time at which each step was first reached. */
    val stepAtMs: Map<FrictionStep, Long>,
    val firstEventAtMs: Long?,
    /** For each event's first appearance: end of the audio that produced it -> emitted. */
    val spokenToEventMs: List<Long>,
    /** Engine processing time per observation, in microseconds (measured, not simulated). */
    val engineMicros: List<Long>,
    val eventsSent: Int,
    val segmentsSent: Int,
    val removedByType: Map<PiiType, Int>,
    val blocked: List<String>,
    val canaryLeaks: List<String>,
    val egressFile: File,
    /** The observations the engine consumed, in the contract's wire format. */
    val observationsFile: File,
) {
    val leakFree: Boolean get() = canaryLeaks.isEmpty() && blocked.isEmpty()
    val passed: Boolean get() = leakFree && (expectedStep == null || expectedStep == finalStep)
}

/**
 * Drives the real engine and the real egress path from two kinds of input:
 *
 *  - **[run] a call script**: simulated ASR -> text extractor (the lexicon by default) ->
 *    observations -> engine, and commits -> privacy filter -> redacted segments. The observations
 *    the engine saw are written to `observations.jsonl`, which is both the baseline a trained
 *    extractor is compared against and a worked example of the contract.
 *  - **[runObservations] an observations file**: whatever produced it (a Python prototype, a
 *    trained tagger, a recording of the lexicon) goes straight into the engine. No text exists in
 *    this mode, so only events leave.
 *
 * Both modes share [Session], so the engine, ladder, uplink and reporting are identical; only
 * the source of observations differs.
 */
class ReplayRunner(
    private val outDir: File,
    private val asr: SimulatedAsr = SimulatedAsr(),
    private val out: PrintStream? = System.out,
    private val salt: ByteArray = "aegis-replay-demo-salt-v1".toByteArray(),
    /** The text-layer extractor used in script mode. Swap in a trained tagger here. */
    private val extractor: () -> SemanticExtractor<TranscriptUpdate> = { LexiconExtractor() },
) {
    private val lexicon = ScamLexicon()

    fun run(script: CallScript): ReplayResult {
        val s = Session(script.name, script.title, "call-" + script.name, script.canaries, script.expectStep, script.prior)
        val privacy = PrivacyFilter(s.callId, salt, lexicon.vocabulary)
        val x = extractor()
        for (timed in asr.stream(s.callId, script)) {
            val u = timed.update
            val obs = x.extract(u)
            s.observe(timed.emitAtMs, obs, text = if (u.isFinal) u.text.lowercase() else null)
            if (u.isFinal) s.send(privacy.onCommit(u)) else privacy.notePartial(u)
            s.send(privacy.flushStale(timed.emitAtMs))
            s.pump()
        }
        s.send(privacy.flush(s.now))
        return s.finish(privacy.stats.removedByType.toMap())
    }

    /**
     * Replay an observations file. An optional first line `{"meta":{...}}` may carry `title`,
     * `expect_step`, `prior` and `canaries`; every other line is one [ObservationCodec] record.
     */
    fun runObservations(file: File): ReplayResult {
        val lines = file.readLines().filter { it.isNotBlank() }
        val meta = lines.firstOrNull()?.let { JsonReader.parse(it) as? Map<*, *> }?.get("meta") as? Map<*, *>
        val records = (if (meta != null) lines.drop(1) else lines).map { ObservationCodec.decode(it) }.sortedBy { it.emitAtMs }
        require(records.isNotEmpty()) { "no observations in $file" }
        val name = file.nameWithoutExtension
        val s = Session(
            name = name,
            title = meta?.get("title") as String? ?: name,
            callId = records.first().observation.callId,
            canaries = (meta?.get("canaries") as? List<*>)?.map { it.toString() }.orEmpty(),
            expectStep = (meta?.get("expect_step") as String?)?.let { FrictionStep.valueOf(it) },
            prior = meta?.get("prior") as Double? ?: 0.0,
        )
        for (r in records) {
            s.observe(r.emitAtMs, r.observation, text = null)
            s.pump()
        }
        return s.finish(emptyMap())
    }

    private inner class Session(
        val name: String,
        val title: String,
        val callId: String,
        private val canaries: List<String>,
        private val expectStep: FrictionStep?,
        prior: Double,
    ) {
        private val dir = File(outDir, name).apply { deleteRecursively(); mkdirs() }
        private val egress = File(dir, "egress.jsonl")
        private val observations = File(dir, "observations.jsonl")
        private val uplink = Uplink(EgressJournal(File(dir, "uplink.journal")), JsonlFileTransport(egress), EgressAuditor(canaries))
        var now = 0L
            private set
        private val engine = FastPathEngine(callId, clockMs = { now })

        private val stepAt = LinkedHashMap<FrictionStep, Long>()
        private val spokenToEvent = mutableListOf<Long>()
        private val engineMicros = mutableListOf<Long>()
        private val blocked = mutableListOf<String>()
        private val firstSeen = HashSet<String>()
        private var firstEventAt: Long? = null
        private var events = 0
        private var segments = 0

        init {
            observations.writeText(Json.obj("meta" to mapOf(
                "title" to title, "expect_step" to expectStep?.name, "prior" to prior, "canaries" to canaries,
            )) + "\n")
            say("")
            say("== $title  ($name)")
            if (prior > 0) {
                val tick = engine.updatePrior(CallerPrior(prior, listOf("pattern-base")))
                if (tick.stepChanged) stepAt.putIfAbsent(tick.snapshot.step, 0L)
                say("  [ 0.0s] caller prior ${"%.2f".format(prior)} (testimony) -> ${tick.snapshot.step}")
            }
        }

        fun observe(emitAtMs: Long, obs: SegmentObservation, text: String?) {
            now = emitAtMs
            observations.appendText(ObservationCodec.encode(obs, emitAtMs) + "\n")
            val tick = engine.onObservation(obs)
            engineMicros += tick.processingNanos / 1_000

            if (obs.isFinal) {
                val what = text ?: obs.tactics.joinToString(" ") { it.tactic.name }.ifEmpty { "(no tactics)" }
                say(String.format("  [%5.1fs] %-6s seg %-3d %s", now / 1000.0, obs.speaker.name, obs.segmentId, what))
            }
            for (e in tick.changedEvents) {
                if (firstSeen.add(e.eventId)) {
                    spokenToEvent += now - obs.audioEndMs
                    if (firstEventAt == null) firstEventAt = now
                }
                if (uplink.submit(EventUpdate(e)) == Uplink.SubmitResult.Queued) events++
                say("           ${describe(e)}")
            }
            if (tick.stepChanged) {
                val s = tick.snapshot
                stepAt.putIfAbsent(s.step, now)
                val banner = if (s.step == FrictionStep.PAUSE) "#### REALITY PAUSE ####" else "^ ${s.step}"
                say(String.format("           %s  risk %.2f  stage %s  next: %s", banner, s.score, s.stage,
                    s.expectedNext.joinToString(", ").ifEmpty { "-" }))
                say("             why: " + s.contributions.take(4).joinToString("; ") { "${it.label} +%.2f".format(it.value) })
            }
        }

        fun send(segs: List<RedactedSegment>) {
            for (s in segs) {
                when (val r = uplink.submit(s)) {
                    is Uplink.SubmitResult.Blocked -> { blocked += r.violations; say("     !! BLOCKED at egress: ${r.violations}") }
                    else -> { segments++; say("     -> deep path [${s.speaker.name.lowercase()}]: ${s.text}") }
                }
            }
        }

        fun pump() { uplink.pump() }

        fun finish(removed: Map<PiiType, Int>): ReplayResult {
            uplink.pump()
            if (engine.contractViolations > 0) say("     !! ${engine.contractViolations} observations broke the extractor contract and were dropped")
            return ReplayResult(
                name = name, title = title, finalStep = engine.snapshot().step, expectedStep = expectStep,
                stepAtMs = stepAt, firstEventAtMs = firstEventAt, spokenToEventMs = spokenToEvent,
                engineMicros = engineMicros, eventsSent = events, segmentsSent = segments,
                removedByType = removed, blocked = blocked, canaryLeaks = scanForCanaries(egress, canaries),
                egressFile = egress, observationsFile = observations,
            ).also { summarize(it) }
        }
    }

    /** Independent of the auditor: reread what actually went out and look for every canary. */
    private fun scanForCanaries(egress: File, canaries: List<String>): List<String> {
        if (!egress.exists()) return emptyList()
        val sent = TextNormalizer.tokens(egress.readText())
        return canaries.filter { c ->
            val toks = TextNormalizer.tokens(c)
            toks.isNotEmpty() && sent.windowed(toks.size).any { it == toks }
        }
    }

    private fun describe(e: SemanticEvent): String {
        val mark = when (e.evidence) {
            Evidence.PROVISIONAL -> "~"
            Evidence.COMMITTED -> "+"
            Evidence.RETRACTED -> "x"
        }
        val q = if (e.qualifier.name == "NONE") "" else ":" + e.qualifier.name
        return "$mark ${e.tactic}$q ${e.evidence.name.lowercase()} %.2f (r${e.revision}, ${e.source})".format(e.confidence)
    }

    private fun summarize(r: ReplayResult) {
        val pct = { xs: List<Long>, p: Double -> if (xs.isEmpty()) 0 else xs.sorted()[((xs.size - 1) * p).toInt()] }
        say("  -- result: final step ${r.finalStep}" + (r.expectedStep?.let { " (expected $it)" } ?: "") +
            if (r.passed) "  [ok]" else "  [FAIL]")
        r.stepAtMs.forEach { (s, t) -> say(String.format("     %-7s reached at %5.1fs", s, t / 1000.0)) }
        r.firstEventAtMs?.let { say(String.format("     first semantic event at %.1fs of call", it / 1000.0)) }
        if (r.spokenToEventMs.isNotEmpty()) {
            say("     audio -> event: p50 ${pct(r.spokenToEventMs, 0.5)} ms, p95 ${pct(r.spokenToEventMs, 0.95)} ms (includes extractor lag)")
        }
        say("     engine per observation: p50 ${pct(r.engineMicros, 0.5)} us, p95 ${pct(r.engineMicros, 0.95)} us, max ${r.engineMicros.maxOrNull() ?: 0} us (measured)")
        say("     egress: ${r.eventsSent} events + ${r.segmentsSent} redacted segments -> ${r.egressFile.path}")
        say("     observations consumed -> ${r.observationsFile.path}")
        if (r.removedByType.isNotEmpty()) say("     PII removed: " + r.removedByType.entries.sortedBy { it.key }.joinToString { "${it.key}=${it.value}" })
        say("     leakage: ${r.canaryLeaks.size} canary leaks, ${r.blocked.size} blocked at egress")
    }

    private fun say(s: String) { out?.println(s) }
}
