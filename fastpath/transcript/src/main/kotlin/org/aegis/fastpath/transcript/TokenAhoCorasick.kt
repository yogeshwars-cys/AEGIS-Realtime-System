package org.aegis.fastpath.transcript

/**
 * Aho-Corasick over tokens instead of characters.
 *
 * A character-level gazetteer has to pad keys and text with spaces so a term only matches as
 * a whole token sequence ("inch" never inside "pinch"). Making the
 * alphabet the token itself gives that property by construction: "pin" cannot fire inside
 * "spinning" because "spinning" is one symbol. One pass over the segment finds every phrase,
 * whatever the dictionary size.
 */
class TokenAhoCorasick<V>(phrases: Map<List<String>, V>) {

    data class Match<V>(val start: Int, val endExclusive: Int, val value: V)

    private val goto = mutableListOf(HashMap<String, Int>())
    private val fail = mutableListOf(0)
    private val out = mutableListOf(mutableListOf<Pair<Int, V>>()) // (phrase length, value)

    init {
        for ((phrase, value) in phrases) {
            require(phrase.isNotEmpty()) { "empty phrase" }
            var node = 0
            for (tok in phrase) {
                node = goto[node].getOrPut(tok) {
                    goto.add(HashMap()); fail.add(0); out.add(mutableListOf())
                    goto.size - 1
                }
            }
            out[node].add(phrase.size to value)
        }
        val queue = ArrayDeque<Int>()
        for (child in goto[0].values) queue.add(child)
        while (queue.isNotEmpty()) {
            val node = queue.removeFirst()
            for ((tok, child) in goto[node]) {
                queue.add(child)
                var f = fail[node]
                while (f != 0 && tok !in goto[f]) f = fail[f]
                val target = goto[f][tok]
                fail[child] = if (target != null && target != child) target else 0
                out[child].addAll(out[fail[child]])
            }
        }
    }

    fun scan(tokens: List<String>): List<Match<V>> {
        val matches = mutableListOf<Match<V>>()
        var node = 0
        tokens.forEachIndexed { i, tok ->
            while (node != 0 && tok !in goto[node]) node = fail[node]
            node = goto[node][tok] ?: 0
            for ((len, value) in out[node]) matches.add(Match(i - len + 1, i + 1, value))
        }
        return matches.sortedWith(compareBy({ it.start }, { -it.endExclusive }))
    }
}
