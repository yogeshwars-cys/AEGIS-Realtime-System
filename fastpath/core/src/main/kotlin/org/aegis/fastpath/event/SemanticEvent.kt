package org.aegis.fastpath.event

import org.aegis.fastpath.util.Json

/**
 * How an event is known.
 *
 * First-hand evidence tiers, applied to a transcript: a
 * [PROVISIONAL] event came from an unstable ASR partial and may be revised away, a
 * [COMMITTED] event came from text the recogniser has finalised. Only committed evidence
 * may authorise the Reality Pause (see [org.aegis.fastpath.risk.EvidenceGate]).
 */
enum class Evidence { PROVISIONAL, COMMITTED, RETRACTED }

/**
 * One semantic finding about the call, and the only thing the fast path itself emits.
 *
 * There is deliberately no string field that could carry transcript text: the tactic is an
 * enum, the identifiers are generated. An event can be sent off the phone as-is.
 *
 * An event is updated in place rather than re-raised: the partial that first spots "any desk"
 * and the commit that confirms it are one event at two revisions, the way an enriched report
 * updates an open incident instead of raising a second alert.
 * [idempotencyKey] is what the receiving side dedupes on.
 */
data class SemanticEvent(
    val eventId: String,
    val callId: String,
    val revision: Int,
    val tactic: Tactic,
    val qualifier: Qualifier,
    val confidence: Double,
    val evidence: Evidence,
    /** Which extractor produced the strongest evidence for this revision ("lexicon", "tagger-v2"). */
    val source: String,
    /** Segment that last changed this event. */
    val segmentId: Int,
    /** Audio span of the text that produced the latest revision, ms from call start. */
    val audioStartMs: Long,
    val audioEndMs: Long,
    /** Engine clock when this revision was produced, ms from call start. */
    val emittedAtMs: Long,
    /** Times this tactic was observed in committed text so far. */
    val occurrences: Int,
) {
    init {
        require(confidence in 0.0..1.0) { "confidence must be 0..1, got $confidence" }
        require(revision >= 1) { "revision starts at 1" }
    }

    val idempotencyKey: String get() = "$eventId#$revision"

    val isLive: Boolean get() = evidence != Evidence.RETRACTED

    fun toJson(): String = Json.obj(
        "type" to "semantic_event",
        "event_id" to eventId,
        "call_id" to callId,
        "revision" to revision,
        "tactic" to tactic.name,
        "qualifier" to qualifier.name,
        "confidence" to confidence,
        "evidence" to evidence.name,
        "source" to source,
        "segment_id" to segmentId,
        "audio_start_ms" to audioStartMs,
        "audio_end_ms" to audioEndMs,
        "emitted_at_ms" to emittedAtMs,
        "occurrences" to occurrences,
    )

    companion object {
        fun idFor(callId: String, tactic: Tactic, qualifier: Qualifier): String =
            "$callId:${tactic.name}:${qualifier.name}"
    }
}
