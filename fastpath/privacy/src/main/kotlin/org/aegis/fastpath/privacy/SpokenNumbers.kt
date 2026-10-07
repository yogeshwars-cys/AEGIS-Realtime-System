package org.aegis.fastpath.privacy

/**
 * Inverse text normalisation for number detection.
 *
 * Streaming ASR writes "account ending four eight two one", never "4821", so a digit regex
 * alone sees nothing. This finds maximal runs of number words and digit tokens and recovers the
 * digits they spell. It is used only to *find* sensitive spans; the output text is rebuilt from
 * the original tokens with those spans replaced, never from these digits.
 *
 * Two readings, chosen per run:
 *  - **digit sequence** ("four eight two one", "double five", "forty eight twenty one") -> the
 *    digits concatenated: 4821, 55, 4821. This is how people read out OTPs, phone, Aadhaar and
 *    account numbers;
 *  - **cardinal** (any run containing hundred / thousand / lakh / crore) -> its value:
 *    "fifty thousand" -> 50000, "four hundred two" -> 402.
 *
 * English number words only. Hindi numerals spoken in a Hinglish call are not covered yet.
 */
object SpokenNumbers {

    data class Run(val start: Int, val endExclusive: Int, val digits: String, val cardinal: Boolean)

    private val units = mapOf(
        "zero" to 0, "oh" to 0, "one" to 1, "two" to 2, "three" to 3, "four" to 4, "five" to 5,
        "six" to 6, "seven" to 7, "eight" to 8, "nine" to 9,
    )
    private val teens = mapOf(
        "ten" to 10, "eleven" to 11, "twelve" to 12, "thirteen" to 13, "fourteen" to 14, "fifteen" to 15,
        "sixteen" to 16, "seventeen" to 17, "eighteen" to 18, "nineteen" to 19,
    )
    private val tens = mapOf(
        "twenty" to 20, "thirty" to 30, "forty" to 40, "fifty" to 50, "sixty" to 60, "seventy" to 70,
        "eighty" to 80, "ninety" to 90,
    )
    private val scales = mapOf(
        "hundred" to 100L, "thousand" to 1_000L, "lakh" to 100_000L, "lakhs" to 100_000L,
        "crore" to 10_000_000L, "crores" to 10_000_000L, "million" to 1_000_000L,
    )
    private val repeaters = mapOf("double" to 2, "triple" to 3)

    private fun isDigits(t: String) = t.isNotEmpty() && t.all { it in '0'..'9' }

    fun isNumberish(t: String): Boolean =
        isDigits(t) || t in units || t in teens || t in tens || t in scales || t in repeaters

    /** True for a token that can only be part of a number ("oh" alone is not). */
    private fun startsRun(tokens: List<String>, i: Int): Boolean {
        val t = tokens[i]
        if (t == "oh") return false
        if (t in repeaters) return tokens.getOrNull(i + 1)?.let { it in units || isDigits(it) } == true
        if (t in scales) return false
        return isNumberish(t)
    }

    fun runs(tokens: List<String>): List<Run> {
        val out = mutableListOf<Run>()
        var i = 0
        while (i < tokens.size) {
            if (!startsRun(tokens, i)) { i++; continue }
            var j = i
            while (j < tokens.size && isNumberish(tokens[j])) j++
            val slice = tokens.subList(i, j)
            val cardinal = slice.any { it in scales }
            val digits = if (cardinal) cardinalValue(slice).toString() else digitSequence(slice)
            if (digits.isNotEmpty()) out.add(Run(i, j, digits, cardinal))
            i = j
        }
        return out
    }

    private fun digitSequence(words: List<String>): String {
        val sb = StringBuilder()
        var pendingTens: Int? = null
        var repeat = 1
        fun flushTens() { pendingTens?.let { sb.append(it) }; pendingTens = null }
        for (w in words) {
            when {
                isDigits(w) -> { flushTens(); sb.append(w.repeat(repeat)); repeat = 1 }
                w in repeaters -> { flushTens(); repeat = repeaters.getValue(w) }
                w in units -> {
                    val u = units.getValue(w)
                    val t = pendingTens
                    if (t != null && u != 0 && repeat == 1) { sb.append(t + u); pendingTens = null }
                    else { flushTens(); sb.append(u.toString().repeat(repeat)); repeat = 1 }
                }
                w in teens -> { flushTens(); sb.append(teens.getValue(w)); repeat = 1 }
                w in tens -> { flushTens(); pendingTens = tens.getValue(w); repeat = 1 }
            }
        }
        flushTens()
        return sb.toString()
    }

    private fun cardinalValue(words: List<String>): Long {
        var total = 0L
        var current = 0L
        for (w in words) {
            when {
                isDigits(w) -> current += w.take(15).toLong()
                w in units -> current += units.getValue(w)
                w in teens -> current += teens.getValue(w)
                w in tens -> current += tens.getValue(w)
                w == "hundred" -> current = maxOf(current, 1) * 100
                w in scales -> { total += maxOf(current, 1) * scales.getValue(w); current = 0 }
            }
        }
        return total + current
    }
}
