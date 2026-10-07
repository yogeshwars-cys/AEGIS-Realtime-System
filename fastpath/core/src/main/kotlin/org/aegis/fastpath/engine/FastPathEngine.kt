package org.aegis.fastpath.engine

import org.aegis.fastpath.event.ManipulationStage
import org.aegis.fastpath.event.SemanticEvent
import org.aegis.fastpath.event.Speaker
import org.aegis.fastpath.event.Tactic
import org.aegis.fastpath.observation.SegmentObservation
import org.aegis.fastpath.prior.CallerPrior
import org.aegis.fastpath.risk.Contribution
import org.aegis.fastpath.risk.EvidenceGate
import org.aegis.fastpath.risk.FastRisk
import org.aegis.fastpath.risk.FrictionLadder
import org.aegis.fastpath.risk.FrictionStep
import org.aegis.fastpath.risk.RiskScore
import org.aegis.fastpath.state.EventFolder
import org.aegis.fastpath.state.ManipulationFsm

/** Everything the phone UI needs to render the fast path at one instant. */
data class FastPathSnapshot(
    val callId: String,
    val stage: ManipulationStage,
    val provisionalStage: ManipulationStage,
    val score: Double,
    val step: FrictionStep,
    val ceiling: FrictionStep,
    val contributions: List<Contribution>,
    val path: List<Tactic>,
    val expectedNext: List<Tactic>,
    val events: List<SemanticEvent>,
)

/** The result of feeding one observation through the engine. */
data class FastPathTick(
    val changedEvents: List<SemanticEvent>,
    val stepChanged: Boolean,
    val snapshot: FastPathSnapshot,
    /** Wall-clock time this observation spent inside the engine. */
    val processingNanos: Long,
)

/**
 * The real-time engine for one call: [SegmentObservation]s in, semantic events and an
 * intervention step out, with no network anywhere on this path.
 *
 * It knows nothing about text, audio or which extractor is running. Swapping the lexicon for a
 * trained tagger, or for a model that reads audio directly, changes the extractor and nothing
 * here. The contract it relies on is documented on [SegmentObservation].
 *
 * Contract breaches are counted, not thrown, because a phone mid-call must keep protecting the
 * user: observations for another call or for a segment that was already finalised are dropped
 * and show up in [contractViolations].
 *
 * Not thread-safe by design: one engine per call, driven by one thread.
 */
class FastPathEngine(
    val callId: String,
    prior: CallerPrior = CallerPrior.NONE,
    /** Milliseconds since call start. Injected so replay and tests control time. */
    private val clockMs: () -> Long,
    private val nanoTime: () -> Long = System::nanoTime,
) {
    private val folder = EventFolder(callId)
    private val fsm = ManipulationFsm()
    private val ladder = FrictionLadder()
    private val finalized = HashSet<Int>()

    var prior: CallerPrior = prior
        private set

    var contractViolations: Int = 0
        private set

    fun onObservation(obs: SegmentObservation): FastPathTick {
        val t0 = nanoTime()
        if (obs.callId != callId || obs.segmentId in finalized) {
            contractViolations++
            return tick(emptyList(), false, t0)
        }
        if (obs.isFinal) finalized.add(obs.segmentId)
        // Tactics are things a caller does to a victim. Victim speech is accepted and ignored:
        // a victim repeating "OTP" is not a request for one.
        if (obs.speaker == Speaker.VICTIM) return tick(emptyList(), false, t0)

        val changed = folder.fold(obs, clockMs())
        return tick(changed, false, t0)
    }

    /** The user asked "is this a scam?": at least VERIFY, immediately. */
    fun userFlagged(): FastPathTick {
        val t0 = nanoTime()
        return tick(emptyList(), ladder.userFlagged(), t0)
    }

    /** A late reputation answer. Only ever raises the prior. */
    fun updatePrior(next: CallerPrior): FastPathTick {
        val t0 = nanoTime()
        if (next.level > prior.level) prior = next
        return tick(emptyList(), false, t0)
    }

    fun snapshot(): FastPathSnapshot = buildSnapshot(FastRisk.score(folder.events, prior))

    private fun tick(changed: List<SemanticEvent>, alreadyChanged: Boolean, t0: Long): FastPathTick {
        val events = folder.events
        fsm.update(events)
        val risk = FastRisk.score(events, prior)
        val committed = FastRisk.score(events, prior, committedOnly = true)
        val ceiling = EvidenceGate.ceiling(events)
        val nudge = ladder.update(risk.score, minOf(FrictionStep.NUDGE, ceiling))
        val firm = ladder.update(committed.score, ceiling)
        return FastPathTick(changed, nudge || firm || alreadyChanged, buildSnapshot(risk), nanoTime() - t0)
    }

    private fun buildSnapshot(risk: RiskScore): FastPathSnapshot {
        val events = folder.events
        val observed = events.filter { it.isLive }.map { it.tactic }.toSet()
        return FastPathSnapshot(
            callId = callId,
            stage = fsm.stage,
            provisionalStage = fsm.provisionalStage,
            score = risk.score,
            step = ladder.step,
            ceiling = EvidenceGate.ceiling(events),
            contributions = risk.contributions,
            path = fsm.path.toList(),
            expectedNext = fsm.expectedNext(observed),
            events = events,
        )
    }
}
