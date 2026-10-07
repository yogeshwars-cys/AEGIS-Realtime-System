package org.aegis.fastpath.state

import org.aegis.fastpath.event.Evidence
import org.aegis.fastpath.event.Qualifier
import org.aegis.fastpath.event.SemanticEvent
import org.aegis.fastpath.event.Tactic
import org.aegis.fastpath.observation.SegmentObservation

/**
 * Folds segment observations into one evolving event per (tactic, qualifier).
 *
 * A provisional-then-confirmed cascade, applied to whatever the extractor reports:
 *  - a tactic in a **non-final** observation opens or raises a [Evidence.PROVISIONAL] event at
 *    once, so risk sees it before the segment settles;
 *  - the segment's **final** observation confirms it ([Evidence.COMMITTED]) under the same event
 *    id or, if the final no longer contains it, [Evidence.RETRACTED]s it;
 *  - repeats in later segments raise confidence and count occurrences; they never open a
 *    second event.
 *
 * A new revision is produced only when something a consumer acts on changes (evidence tier or
 * confidence), so the uplink carries deltas, not a stream of identical states.
 */
class EventFolder(private val callId: String) {

    private class Slot(
        var event: SemanticEvent,
        /** Segment whose non-final observation opened the provisional state, if any. */
        var provisionalSegment: Int?,
    )

    private val slots = LinkedHashMap<Pair<Tactic, Qualifier>, Slot>()

    val events: List<SemanticEvent> get() = slots.values.map { it.event }

    /** Fold one observation. Returns the events that changed. */
    fun fold(obs: SegmentObservation, nowMs: Long): List<SemanticEvent> {
        val changed = mutableListOf<SemanticEvent>()
        val seen = HashSet<Pair<Tactic, Qualifier>>()
        val segmentId = obs.segmentId
        val isFinal = obs.isFinal

        for (hit in obs.tactics) {
            val key = hit.tactic to hit.qualifier
            seen.add(key)
            val evidence = if (isFinal) Evidence.COMMITTED else Evidence.PROVISIONAL
            val slot = slots[key]
            if (slot == null) {
                val ev = SemanticEvent(
                    eventId = SemanticEvent.idFor(callId, hit.tactic, hit.qualifier),
                    callId = callId,
                    revision = 1,
                    tactic = hit.tactic,
                    qualifier = hit.qualifier,
                    confidence = hit.confidence,
                    evidence = evidence,
                    source = hit.source,
                    segmentId = segmentId,
                    audioStartMs = obs.audioStartMs,
                    audioEndMs = obs.audioEndMs,
                    emittedAtMs = nowMs,
                    occurrences = if (isFinal) 1 else 0,
                )
                slots[key] = Slot(ev, if (isFinal) null else segmentId)
                changed.add(ev)
                continue
            }

            val old = slot.event
            // Committed evidence is only ever revised by more committed evidence.
            if (old.evidence == Evidence.COMMITTED && !isFinal) continue
            val newEvidence = if (old.evidence == Evidence.COMMITTED) Evidence.COMMITTED else evidence
            val conf = if (old.evidence == Evidence.RETRACTED) hit.confidence else maxOf(old.confidence, hit.confidence)
            val next = old.copy(
                confidence = conf,
                evidence = newEvidence,
                source = if (conf > old.confidence || old.evidence == Evidence.RETRACTED) hit.source else old.source,
                // Only settled readings count as occurrences.
                occurrences = old.occurrences + if (isFinal) 1 else 0,
            )
            if (!isFinal) slot.provisionalSegment = segmentId
            if (isFinal && slot.provisionalSegment == segmentId) slot.provisionalSegment = null

            if (next.evidence != old.evidence || next.confidence > old.confidence + EPS) {
                slot.event = next.copy(
                    revision = old.revision + 1,
                    segmentId = segmentId,
                    audioStartMs = obs.audioStartMs,
                    audioEndMs = obs.audioEndMs,
                    emittedAtMs = nowMs,
                )
                changed.add(slot.event)
            } else {
                slot.event = next // occurrence count only: not a revision
            }
        }

        if (isFinal) {
            // Provisional events this segment opened but its final reading did not confirm.
            for ((key, slot) in slots) {
                if (key in seen) continue
                if (slot.event.evidence == Evidence.PROVISIONAL && slot.provisionalSegment == segmentId) {
                    slot.event = slot.event.copy(
                        revision = slot.event.revision + 1,
                        evidence = Evidence.RETRACTED,
                        segmentId = segmentId,
                        audioStartMs = obs.audioStartMs,
                        audioEndMs = obs.audioEndMs,
                        emittedAtMs = nowMs,
                    )
                    slot.provisionalSegment = null
                    changed.add(slot.event)
                }
            }
        }
        return changed
    }

    private companion object {
        const val EPS = 1e-9
    }
}
