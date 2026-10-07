package org.aegis.fastpath.observation

import org.aegis.fastpath.event.Qualifier
import org.aegis.fastpath.event.Speaker
import org.aegis.fastpath.event.Tactic
import org.aegis.fastpath.util.Json
import org.aegis.fastpath.util.JsonReader

/**
 * One-line JSON form of [SegmentObservation], so an extractor written in anything (a Python
 * prototype on a laptop, a model on another device) can drive the engine, and so the lexicon's
 * output can be recorded as a baseline to compare a trained extractor against.
 *
 * ```
 * {"call_id":"c1","segment_id":3,"speaker":"CALLER","final":true,
 *  "audio_start_ms":9100,"audio_end_ms":12600,"emit_at_ms":13200,
 *  "tactics":[{"tactic":"URGENCY","qualifier":"NONE","confidence":0.85,"source":"tagger-v1"}]}
 * ```
 * `emit_at_ms` (when the extractor produced the reading, ms from call start) is optional and
 * defaults to `audio_end_ms`; replay uses it as the engine clock. `qualifier` defaults to NONE.
 */
object ObservationCodec {

    data class Timed(val emitAtMs: Long, val observation: SegmentObservation)

    fun encode(obs: SegmentObservation, emitAtMs: Long = obs.audioEndMs): String = Json.obj(
        "call_id" to obs.callId,
        "segment_id" to obs.segmentId,
        "speaker" to obs.speaker.name,
        "final" to obs.isFinal,
        "audio_start_ms" to obs.audioStartMs,
        "audio_end_ms" to obs.audioEndMs,
        "emit_at_ms" to emitAtMs,
        "tactics" to obs.tactics.map {
            mapOf("tactic" to it.tactic.name, "qualifier" to it.qualifier.name, "confidence" to it.confidence, "source" to it.source)
        },
    )

    fun decode(line: String): Timed {
        val m = JsonReader.parse(line) as? Map<*, *> ?: error("observation must be a JSON object")
        fun long(k: String) = (m[k] as? Double ?: error("missing number '$k'")).toLong()
        val tactics = (m["tactics"] as? List<*> ?: emptyList<Any>()).map { t ->
            val o = t as? Map<*, *> ?: error("tactic must be an object")
            ObservedTactic(
                tactic = Tactic.valueOf(o["tactic"] as String),
                qualifier = (o["qualifier"] as String?)?.let { Qualifier.valueOf(it) } ?: Qualifier.NONE,
                confidence = o["confidence"] as Double,
                source = o["source"] as String? ?: "external",
            )
        }
        val obs = SegmentObservation(
            callId = m["call_id"] as String,
            segmentId = long("segment_id").toInt(),
            speaker = Speaker.valueOf(m["speaker"] as String),
            isFinal = m["final"] as Boolean,
            audioStartMs = long("audio_start_ms"),
            audioEndMs = long("audio_end_ms"),
            tactics = tactics,
        )
        val emit = (m["emit_at_ms"] as? Double)?.toLong() ?: obs.audioEndMs
        return Timed(emit, obs)
    }
}
