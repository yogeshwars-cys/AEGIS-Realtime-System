package org.aegis.fastpath.observation

import org.aegis.fastpath.event.Qualifier
import org.aegis.fastpath.event.Speaker
import org.aegis.fastpath.event.Tactic

/**
 * One tactic an extractor sees in a segment.
 *
 * [source] names the extractor and its version ("lexicon", "tagger-v2"), so an event can always
 * be traced to what produced it. Letters, digits, '-', '_', '.', '@' only: it travels in events.
 */
data class ObservedTactic(
    val tactic: Tactic,
    val qualifier: Qualifier = Qualifier.NONE,
    val confidence: Double,
    val source: String,
) {
    init {
        require(confidence in 0.0..1.0) { "confidence must be 0..1, got $confidence" }
        require(SOURCE.matches(source)) { "source must match ${SOURCE.pattern}, got '$source'" }
    }

    private companion object {
        val SOURCE = Regex("[A-Za-z0-9._@-]{1,40}")
    }
}

/**
 * **The engine's only input, and the contract every semantic extractor implements.**
 *
 * The engine does not know whether this came from a keyword lexicon, a fine-tuned text tagger,
 * an end-to-end speech model or a script. Whatever the extractor is, it reports, per segment of
 * the conversation:
 *
 *  - [segmentId]: unique and increasing within a call. A segment is one utterance or one
 *    endpointed stretch of speech; the extractor decides what a segment is.
 *  - [isFinal]: `false` for an early, revisable reading (an ASR partial, a streaming model's
 *    interim output); `true` exactly once per segment for the settled reading. Extractors that
 *    only produce settled output simply send finals; they lose the early provisional signal,
 *    nothing else.
 *  - [tactics]: the **complete** set of tactics seen in the segment so far, not a delta. A
 *    final that omits a tactic an earlier partial of the same segment reported retracts it.
 *    At most one entry per (tactic, qualifier).
 *  - [speaker]: who said it. Only [Speaker.CALLER] (and [Speaker.UNKNOWN] on a single-channel
 *    capture) can produce caller tactics; victim observations are accepted and ignored.
 *  - [audioStartMs] / [audioEndMs]: the span of call audio the reading covers, ms from call
 *    start. Used for latency measurement, never for decisions.
 *  - confidences in each [ObservedTactic] should be calibrated: 0.9 should be right about nine
 *    times in ten. The risk weights assume it.
 */
data class SegmentObservation(
    val callId: String,
    val segmentId: Int,
    val speaker: Speaker,
    val isFinal: Boolean,
    val audioStartMs: Long,
    val audioEndMs: Long,
    val tactics: List<ObservedTactic>,
) {
    init {
        require(segmentId >= 0) { "segmentId must be >= 0" }
        require(audioEndMs >= audioStartMs) { "audio span is reversed" }
        val keys = tactics.map { it.tactic to it.qualifier }
        require(keys.size == keys.toSet().size) { "at most one entry per (tactic, qualifier) per observation" }
    }
}

/**
 * Anything that turns some input into observations: the lexicon over transcript text today, a
 * trained tagger tomorrow, possibly a model over audio frames later. One extractor instance per
 * call. Must not throw on ordinary input; [CompositeExtractor] contains it if it does.
 */
fun interface SemanticExtractor<I> {
    fun extract(input: I): SegmentObservation
}

/**
 * Runs several extractors over the same input and merges them into one observation, strongest
 * confidence per (tactic, qualifier). Merging *before* the engine matters: two extractors
 * reporting the same final separately would make one retract what the other just confirmed.
 *
 * An extractor that throws contributes nothing to that segment and is counted in [failures], so
 * a broken model shows up instead of silently degrading to the lexicon.
 */
class CompositeExtractor<I>(private val extractors: List<SemanticExtractor<I>>) : SemanticExtractor<I> {
    init {
        require(extractors.isNotEmpty()) { "need at least one extractor" }
    }

    var failures: Int = 0
        private set

    override fun extract(input: I): SegmentObservation {
        var base: SegmentObservation? = null
        val all = mutableListOf<ObservedTactic>()
        for (x in extractors) {
            val obs = try { x.extract(input) } catch (t: Throwable) { failures++; null } ?: continue
            if (base == null) base = obs
            else require(obs.segmentId == base.segmentId && obs.isFinal == base.isFinal) {
                "extractors disagree on which segment this input is"
            }
            all += obs.tactics
        }
        val b = base ?: error("every extractor failed on this input")
        val merged = all.groupBy { it.tactic to it.qualifier }.map { (_, g) -> g.maxBy { it.confidence } }
        return b.copy(tactics = merged)
    }
}
