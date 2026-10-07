package org.aegis.fastpath.event

/**
 * Where a scam call is in its workflow. Ordered: a call only ever moves forward through
 * these within one session, because the evidence for an earlier stage does not stop being
 * true when a later stage begins.
 */
enum class ManipulationStage {
    IDLE,
    /** A pretext is established: who the caller claims to be, or what they offer. */
    CONTACT,
    /** Time pressure or a threat: the victim is pushed to act before thinking. */
    PRESSURE,
    /** The victim is cut off from anyone who could interrupt: stay on the line, tell nobody. */
    CONTROL,
    /** The ask: remote access, a credential, or money. */
    EXTRACTION,
}

/**
 * The semantic vocabulary of the fast path. Every event that leaves the phone is one of
 * these plus an optional [Qualifier], never free text.
 *
 * [weight] is the tactic's contribution to the noisy-OR risk score at full confidence. The
 * numbers are a starting point to be tuned against the replay scripts, not a measurement.
 */
enum class Tactic(val stage: ManipulationStage, val weight: Double) {
    AUTHORITY_CLAIM(ManipulationStage.CONTACT, 0.25),
    REWARD_LURE(ManipulationStage.CONTACT, 0.30),
    URGENCY(ManipulationStage.PRESSURE, 0.30),
    THREAT(ManipulationStage.PRESSURE, 0.35),
    ISOLATION(ManipulationStage.CONTROL, 0.45),
    SECRECY(ManipulationStage.CONTROL, 0.45),
    VERIFICATION_BYPASS(ManipulationStage.CONTROL, 0.45),
    REMOTE_ACCESS_REQUEST(ManipulationStage.EXTRACTION, 0.60),
    CREDENTIAL_REQUEST(ManipulationStage.EXTRACTION, 0.65),
    PAYMENT_REQUEST(ManipulationStage.EXTRACTION, 0.60),
}

/** Who the caller claims to be. Only meaningful on [Tactic.AUTHORITY_CLAIM]. */
enum class Qualifier { NONE, BANK, POLICE, GOVT, COURIER, TELECOM }

/** Which side of the call said it. Only the caller's words produce tactics. */
enum class Speaker { CALLER, VICTIM, UNKNOWN }
