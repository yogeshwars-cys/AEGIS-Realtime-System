package org.aegis.fastpath.state

import org.aegis.fastpath.event.Evidence
import org.aegis.fastpath.event.ManipulationStage
import org.aegis.fastpath.event.SemanticEvent
import org.aegis.fastpath.event.Tactic

/**
 * Where the call is in the scam workflow, derived from the live events.
 *
 * The stage is the furthest stage any committed tactic belongs to, and it only moves forward
 * within a call. [path] is the order in which tactics were first committed. That ordered
 * sequence, not the transcript, is the call's behavioural fingerprint, and it is what the deep
 * path's Scam DNA matcher consumes.
 *
 * [expectedNext] is a static, heuristic look-ahead (what typically follows this stage). It is a
 * cue for the UI, not ShadowPath: real next-action prediction lives in the deep path.
 */
class ManipulationFsm {

    var stage: ManipulationStage = ManipulationStage.IDLE
        private set

    /** Furthest stage including provisional evidence. For display only; never gates anything. */
    var provisionalStage: ManipulationStage = ManipulationStage.IDLE
        private set

    private val pathList = mutableListOf<Tactic>()
    val path: List<Tactic> get() = pathList

    fun update(events: Collection<SemanticEvent>) {
        for (e in events) {
            if (e.evidence == Evidence.COMMITTED) {
                if (e.tactic.stage > stage) stage = e.tactic.stage
                if (e.tactic !in pathList) pathList.add(e.tactic)
            }
        }
        val live = events.filter { it.isLive }.maxOfOrNull { it.tactic.stage } ?: ManipulationStage.IDLE
        provisionalStage = maxOf(stage, live)
    }

    fun expectedNext(observed: Set<Tactic>): List<Tactic> {
        val candidates = when (stage) {
            ManipulationStage.IDLE -> listOf(Tactic.AUTHORITY_CLAIM, Tactic.REWARD_LURE)
            ManipulationStage.CONTACT -> listOf(Tactic.URGENCY, Tactic.THREAT)
            ManipulationStage.PRESSURE -> listOf(Tactic.ISOLATION, Tactic.SECRECY, Tactic.REMOTE_ACCESS_REQUEST)
            ManipulationStage.CONTROL -> listOf(Tactic.REMOTE_ACCESS_REQUEST, Tactic.CREDENTIAL_REQUEST, Tactic.PAYMENT_REQUEST)
            ManipulationStage.EXTRACTION -> listOf(Tactic.CREDENTIAL_REQUEST, Tactic.PAYMENT_REQUEST, Tactic.REMOTE_ACCESS_REQUEST)
        }
        return candidates.filter { it !in observed }
    }
}
