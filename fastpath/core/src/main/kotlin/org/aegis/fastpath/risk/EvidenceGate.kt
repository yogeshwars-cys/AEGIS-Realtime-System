package org.aegis.fastpath.risk

import org.aegis.fastpath.event.Evidence
import org.aegis.fastpath.event.ManipulationStage
import org.aegis.fastpath.event.SemanticEvent

/**
 * What a given tier of knowledge is allowed to authorise.
 *
 * A first-hand gate: testimony
 * may raise suspicion and add friction, but only first-hand observation may take the strongest
 * action. Here the strongest action is the Reality Pause, and the tiers are:
 *
 *  - **committed** evidence: words the recogniser finalised, said on this call;
 *  - **provisional** evidence: an unstable ASR partial;
 *  - **testimony**: the caller prior (reputation, telecom flags).
 *
 * Two structural rules, enforced as caps on the ladder rather than as high thresholds, so no
 * amount of weaker evidence can arithmetically tip into the step above it:
 *
 *  1. Provisional evidence and testimony on their own move the ladder no further than
 *     [FrictionStep.NUDGE]. The ladder never steps back down within a call, so anything above a
 *     nudge has to rest on words the recogniser will not revise away. (The engine scores
 *     committed evidence plus prior separately for exactly this; see [FastRisk.score].)
 *  2. The Reality Pause needs a *pattern*, not a keyword: a committed extraction tactic (remote
 *     access, credential, payment) **and** a committed pressure or control tactic. A courier
 *     asking for the delivery OTP is an extraction tactic with no manipulation around it; it can
 *     reach VERIFY, never PAUSE.
 */
object EvidenceGate {

    fun ceiling(events: Collection<SemanticEvent>): FrictionStep {
        val committed = events.filter { it.evidence == Evidence.COMMITTED }
        if (committed.isEmpty()) return FrictionStep.NUDGE
        val extraction = committed.any { it.tactic.stage == ManipulationStage.EXTRACTION }
        val manipulation = committed.any {
            it.tactic.stage == ManipulationStage.PRESSURE || it.tactic.stage == ManipulationStage.CONTROL
        }
        return if (extraction && manipulation) FrictionStep.PAUSE else FrictionStep.VERIFY
    }
}
