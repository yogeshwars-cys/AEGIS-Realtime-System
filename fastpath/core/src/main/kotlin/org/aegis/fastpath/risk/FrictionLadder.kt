package org.aegis.fastpath.risk

/**
 * The intervention ladder, friction first (step-up -> hold -> freeze, cast for a phone
 * call). Each step is a stronger interruption of the victim, so each needs more evidence.
 */
enum class FrictionStep(val threshold: Double) {
    NONE(0.0),
    /** A quiet banner: "this call shows signs of pressure". */
    NUDGE(0.30),
    /** Guided verification: "did you initiate this call? banks never ask for…" */
    VERIFY(0.55),
    /** The Reality Pause: full-screen interruption before the victim acts. */
    PAUSE(0.75),
}

/**
 * Turns the risk score into the step the phone should be showing.
 *
 * A plain hysteresis gate would use a deadband so the step could not flap on a score resting
 * near a threshold. Inside one call the requirement is stronger: the victim must never see a
 * warning appear, vanish and reappear, and a scammer must not be able to talk the risk back down ("relax, this is just routine"). So the ladder is a
 * ratchet. It climbs, it never descends until the call ends, and [transitions] counts every
 * climb so a jittery configuration is visible in the replay output.
 *
 * [EvidenceGate]'s ceiling is applied before the ratchet, so a step above what the evidence
 * authorises can never be reached even transiently. [userFlagged] is the manual path, an SOS:
 * the user tapping "is this a scam?" goes straight to VERIFY without climbing through the score.
 */
class FrictionLadder {

    var step: FrictionStep = FrictionStep.NONE
        private set

    var transitions: Int = 0
        private set

    /** Fold in the current score and ceiling; returns true if the step changed. */
    fun update(score: Double, ceiling: FrictionStep): Boolean {
        val byScore = FrictionStep.entries.last { score >= it.threshold }
        val target = minOf(byScore, ceiling)
        return raiseTo(target)
    }

    fun userFlagged(): Boolean = raiseTo(FrictionStep.VERIFY)

    private fun raiseTo(target: FrictionStep): Boolean {
        if (target <= step) return false
        step = target
        transitions++
        return true
    }
}
