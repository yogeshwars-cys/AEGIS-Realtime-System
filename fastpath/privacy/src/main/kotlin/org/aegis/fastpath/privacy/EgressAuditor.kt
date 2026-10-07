package org.aegis.fastpath.privacy

import org.aegis.fastpath.transcript.TextNormalizer

/**
 * Last check before anything is journaled for upload: rescans each payload for what the filter
 * should have removed. It is independent of [PiiDetector] on purpose; a second, cruder rule set
 * catches the first one's blind spots instead of repeating them.
 *
 * [canaries] are known fake identities planted in test calls ("Ravindra Kumar", a fake Aadhaar).
 * The leakage metric is `leaked canaries / planted canaries`, target zero.
 */
class EgressAuditor(canaries: Collection<String> = emptyList()) {

    private val canaryTokens: List<List<String>> = canaries.map { TextNormalizer.tokens(it) }.filter { it.isNotEmpty() }

    data class Verdict(val ok: Boolean, val violations: List<String>)

    fun check(payload: EgressPayload): Verdict = when (payload) {
        // Events have no text field. Nothing to scan.
        is EventUpdate -> Verdict(true, emptyList())
        is RedactedSegment -> checkText(payload.text)
    }

    fun checkText(text: String): Verdict {
        val bare = text.replace(PLACEHOLDER, " ")
        val violations = mutableListOf<String>()
        if (RAW_DIGITS.containsMatchIn(bare)) violations.add("raw digit run")
        if ('@' in bare) violations.add("raw handle")
        val tokens = TextNormalizer.tokens(bare)
        if (SpokenNumbers.runs(tokens).any { it.digits.length >= 3 }) violations.add("spoken digit run")
        for (c in canaryTokens) {
            if (PiiDetector.indexOfSequence(tokens, c, 0) >= 0) violations.add("canary: " + c.joinToString(" "))
        }
        return Verdict(violations.isEmpty(), violations)
    }

    private companion object {
        val PLACEHOLDER = Regex("\\[[^\\]]*\\]")
        val RAW_DIGITS = Regex("[0-9]{3,}")
    }
}
