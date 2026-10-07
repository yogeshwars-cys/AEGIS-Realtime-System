package org.aegis.fastpath.privacy

/**
 * What a sensitive span is. [hashedWhenCallers] marks identifiers that, when they belong to the
 * *caller*, are worth keeping as a salted hash: the UPI handle a scammer asks you to pay, the
 * number they ask you to call back, the alias they use. Those link incidents across victims.
 * Everything that belongs to the victim is replaced outright.
 */
enum class PiiType(val label: String, val hashedWhenCallers: Boolean = false) {
    PERSON("PERSON"),
    CALLER_ALIAS("CALLER_ALIAS", hashedWhenCallers = true),
    PHONE("PHONE", hashedWhenCallers = true),
    UPI("UPI", hashedWhenCallers = true),
    ACCOUNT("ACCOUNT", hashedWhenCallers = true),
    AADHAAR("AADHAAR"),
    PAN("PAN"),
    CARD("CARD"),
    ACCT_LAST4("ACCT_LAST4"),
    OTP("OTP"),
    EMAIL("EMAIL"),
    ADDRESS("ADDRESS"),
    DOB("DOB"),
    NUMBER("NUMBER"),
    AMOUNT("AMOUNT"),
}

/** Whose identifier a span is. Decides placeholder versus salted hash. */
enum class Owner { CALLER, VICTIM, UNKNOWN }

data class PiiSpan(
    val start: Int,
    val endExclusive: Int,
    val type: PiiType,
    val owner: Owner,
    /** Normalised value, used only on the phone to number placeholders and key hashes. */
    val value: String,
)
