package org.aegis.fastpath.transcript

/**
 * Turns ASR output into the token stream every matcher in the fast path reads.
 *
 * Streaming recognisers emit no reliable punctuation or casing, so nothing downstream may
 * depend on either: lower-case, apostrophes dropped ("don't" -> "dont", which is how the
 * lexicon spells it too), everything else that is not a letter or digit becomes a break.
 * '@' survives inside a token so a literal UPI handle or email stays one token for the
 * privacy filter.
 */
object TextNormalizer {
    private val apostrophes = Regex("[‘’'`]")
    private val breaks = Regex("[^\\p{L}\\p{Nd}@]+")

    fun tokens(text: String): List<String> =
        text.lowercase()
            .replace(apostrophes, "")
            .replace(breaks, " ")
            .split(' ')
            .filter { it.isNotEmpty() }

    fun normalize(text: String): String = tokens(text).joinToString(" ")
}
