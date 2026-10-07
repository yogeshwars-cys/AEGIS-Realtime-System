package org.aegis.fastpath.util

/**
 * Just enough JSON writing for the flat payloads the phone emits. No parser and no
 * reflection, so core keeps its no-third-party-runtime rule.
 */
object Json {
    fun obj(vararg fields: Pair<String, Any?>): String = buildString {
        append('{')
        fields.forEachIndexed { i, (k, v) ->
            if (i > 0) append(',')
            append(str(k)).append(':').append(value(v))
        }
        append('}')
    }

    fun value(v: Any?): String = when (v) {
        null -> "null"
        is String -> str(v)
        is Boolean -> v.toString()
        is Int, is Long -> v.toString()
        is Double -> if (v.isFinite()) "%.4f".format(java.util.Locale.ROOT, v) else "null"
        is Map<*, *> -> v.entries.joinToString(",", "{", "}") { (k, x) -> str(k.toString()) + ":" + value(x) }
        is Iterable<*> -> v.joinToString(",", "[", "]") { value(it) }
        is Enum<*> -> str(v.name)
        else -> str(v.toString())
    }

    fun str(s: String): String = buildString(s.length + 2) {
        append('"')
        for (c in s) {
            when (c) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (c < ' ') append("\\u%04x".format(c.code)) else append(c)
            }
        }
        append('"')
    }
}
