package org.aegis.fastpath.privacy

import org.aegis.fastpath.event.SemanticEvent
import org.aegis.fastpath.event.Speaker
import org.aegis.fastpath.util.Json

/**
 * The only things that may leave the phone.
 *
 * Enforced by structure: the uplink's only entry point takes an
 * [EgressPayload], the interface is sealed, and the one text-carrying implementation,
 * [RedactedSegment], has an `internal` constructor, so nothing outside this module can build
 * one. A raw transcript cannot be handed to the uplink because no code path can turn it into
 * an [EgressPayload] except [PrivacyFilter].
 */
sealed interface EgressPayload {
    /** What the receiver dedupes on. A retry after a lost ack must reuse it. */
    val idempotencyKey: String
    fun toJson(): String
}

/** A semantic event, sent as-is: it has no field that can carry transcript text. */
class EventUpdate(val event: SemanticEvent) : EgressPayload {
    override val idempotencyKey: String get() = event.idempotencyKey
    override fun toJson(): String = event.toJson()
}

/** One stretch of transcript after the on-device filter. */
class RedactedSegment internal constructor(
    val callId: String,
    val speaker: Speaker,
    /** Per-speaker sequence number of emitted segments in this call. */
    val seq: Int,
    /** Normalised, lower-case text with every sensitive span replaced. */
    val text: String,
    val audioStartMs: Long,
    val audioEndMs: Long,
    /** Count of each kind of span removed, for the leakage report. Types only, never values. */
    val removed: Map<PiiType, Int>,
) : EgressPayload {
    override val idempotencyKey: String get() = "$callId:seg:${speaker.name}:$seq"

    override fun toJson(): String = Json.obj(
        "type" to "redacted_segment",
        "call_id" to callId,
        "speaker" to speaker.name,
        "seq" to seq,
        "text" to text,
        "audio_start_ms" to audioStartMs,
        "audio_end_ms" to audioEndMs,
        "removed" to removed.mapKeys { it.key.name },
    )
}
