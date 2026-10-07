package org.aegis.fastpath.risk

import org.aegis.fastpath.event.Evidence
import org.aegis.fastpath.event.SemanticEvent
import org.aegis.fastpath.prior.CallerPrior

/** One line of the "why" a risk score carries. */
data class Contribution(val label: String, val value: Double)

data class RiskScore(val score: Double, val contributions: List<Contribution>)

/**
 * Cumulative risk over the call, as a noisy-OR over *distinct* tactics.
 *
 * Two design rules are built in:
 *
 *  - **No running baseline.** An EMA baseline is a transient detector only: it re-normalises
 *    any sustained signal away in about twenty ticks. A scam call is exactly
 *    a slow, sustained ramp (rapport, then pressure, then the ask), so risk here accumulates
 *    state instead of measuring deviation from a moving average.
 *  - **No volume leak.** Raw counts rank by volume rather than by signal: a long call that
 *    says "OTP" ten times would score ten times higher. Each tactic contributes once, at its
 *    best confidence; repeats only raise that confidence.
 *
 * Provisional evidence is discounted, retracted evidence is ignored, and the caller prior
 * enters as one more noisy-OR term, capped by [PRIOR_WEIGHT].
 */
object FastRisk {
    const val PROVISIONAL_DISCOUNT = 0.6
    const val PRIOR_WEIGHT = 0.35

    /**
     * [committedOnly] drops provisional evidence entirely. The ladder climbs past NUDGE only on
     * that score; the full score (with discounted partials) is what the UI shows.
     */
    fun score(
        events: Collection<SemanticEvent>,
        prior: CallerPrior = CallerPrior.NONE,
        committedOnly: Boolean = false,
    ): RiskScore {
        val terms = mutableListOf<Contribution>()
        for (e in events) {
            if (!e.isLive) continue
            if (committedOnly && e.evidence != Evidence.COMMITTED) continue
            val discount = if (e.evidence == Evidence.PROVISIONAL) PROVISIONAL_DISCOUNT else 1.0
            val label = e.tactic.name + (if (e.qualifier.name != "NONE") ":" + e.qualifier.name else "") +
                (if (e.evidence == Evidence.PROVISIONAL) " (provisional)" else "")
            terms.add(Contribution(label, e.tactic.weight * e.confidence * discount))
        }
        if (prior.level > 0.0) {
            terms.add(Contribution("CALLER_PRIOR" + prior.sources.joinToString(",", "[", "]"), prior.level * PRIOR_WEIGHT))
        }
        val survival = terms.fold(1.0) { acc, c -> acc * (1.0 - c.value.coerceIn(0.0, 1.0)) }
        return RiskScore(1.0 - survival, terms.sortedByDescending { it.value })
    }
}
