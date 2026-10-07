package org.aegis.fastpath.prior

/**
 * What is known about the caller before or outside the conversation: number reputation from
 * the pattern base, a telecom risk flag, device signals such as a CNAP name mismatch.
 *
 * This is testimony, not observation. It may raise the starting risk and make the ladder
 * quicker to react, but [org.aegis.fastpath.risk.EvidenceGate] never lets it authorise the
 * Reality Pause on its own, and a clean reputation never lowers risk: scammers spoof real
 * numbers, rotate fresh SIMs, and numbers get recycled to new owners.
 */
data class CallerPrior(
    /** 0 = nothing known, 1 = strongest available indication of fraud. */
    val level: Double,
    /** Which sources contributed, for the explanation. Enum-like labels, never a number. */
    val sources: List<String> = emptyList(),
) {
    init {
        require(level in 0.0..1.0) { "prior level must be 0..1, got $level" }
    }

    companion object {
        val NONE = CallerPrior(0.0)
    }
}

/** A provider of [CallerPrior]. Looked up when the call starts; must never block the fast path. */
fun interface ReputationSource {
    /** [numberKey] is a salted hash of the caller's number, never the number itself. */
    fun lookup(numberKey: String): CallerPrior?
}
