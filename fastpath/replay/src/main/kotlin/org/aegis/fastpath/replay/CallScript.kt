package org.aegis.fastpath.replay

import org.aegis.fastpath.event.Speaker
import org.aegis.fastpath.transcript.TranscriptUpdate
import org.aegis.fastpath.risk.FrictionStep
import java.io.File

/**
 * A scripted call: who says what, when, and what the fast path is expected to do about it.
 *
 * ```
 * # title: SBI KYC freeze, then AnyDesk
 * # expect-step: PAUSE
 * # canary: ravindra
 * # prior: 0.0
 * 0.0 CALLER: Hello, am I speaking with Ravindra Kumar?
 * +0.5 VICTIM: Yes, speaking.
 * ```
 * A leading number is the utterance's start in seconds; `+n` starts it n seconds after the
 * previous utterance ends. Write numbers as words, the way a streaming recogniser outputs them.
 */
data class CallScript(
    val name: String,
    val title: String,
    val expectStep: FrictionStep?,
    val canaries: List<String>,
    val prior: Double,
    val utterances: List<Utterance>,
) {
    data class Utterance(val startMs: Long, val speaker: Speaker, val text: String)

    companion object {
        private val line = Regex("""^(\+?)(\d+(?:\.\d+)?)\s+(CALLER|VICTIM|UNKNOWN)\s*:\s*(.+)$""")

        fun parse(file: File): CallScript = parse(file.nameWithoutExtension, file.readLines())

        fun parse(name: String, lines: List<String>): CallScript {
            var title = name
            var expect: FrictionStep? = null
            var prior = 0.0
            val canaries = mutableListOf<String>()
            val utterances = mutableListOf<Utterance>()
            var lastEnd = 0L
            for ((n, raw) in lines.withIndex()) {
                val l = raw.trim()
                if (l.isEmpty()) continue
                if (l.startsWith("#")) {
                    val body = l.removePrefix("#").trim()
                    val key = body.substringBefore(':').trim().lowercase()
                    val value = body.substringAfter(':', "").trim()
                    when (key) {
                        "title" -> title = value
                        "expect-step" -> expect = FrictionStep.valueOf(value.uppercase())
                        "canary" -> canaries.add(value)
                        "prior" -> prior = value.toDouble()
                    }
                    continue
                }
                val m = line.matchEntire(l) ?: error("$name:${n + 1}: cannot parse '$l'")
                val (rel, secs, who, text) = m.destructured
                val offset = (secs.toDouble() * 1000).toLong()
                val start = if (rel == "+") lastEnd + offset else offset
                val u = Utterance(start, Speaker.valueOf(who), text)
                utterances.add(u)
                lastEnd = start + SimulatedAsr.durationMs(text)
            }
            return CallScript(name, title, expect, canaries, prior, utterances)
        }
    }
}

/**
 * Stands in for the streaming recogniser so the whole fast path runs on a laptop.
 *
 * Words are spread at a speaking rate; a partial (full hypothesis so far) arrives [partialLagMs]
 * after each word ends; the commit arrives [endpointMs] after the utterance ends, which is how an
 * endpointing streaming transducer behaves. Output is upper-case without punctuation, like a
 * Zipformer, so nothing downstream can lean on formatting the real ASR will not give it.
 *
 * These lags are assumptions, not measurements. The real numbers come from sherpa-onnx on the
 * phone, and replay reports them separately from the engine's own measured processing time.
 */
class SimulatedAsr(
    private val partialLagMs: Long = 300,
    private val endpointMs: Long = 600,
) {
    data class Timed(val emitAtMs: Long, val update: TranscriptUpdate)

    fun stream(callId: String, script: CallScript): List<Timed> {
        val out = mutableListOf<Timed>()
        script.utterances.forEachIndexed { seg, u ->
            val words = asrWords(u.text)
            if (words.isEmpty()) return@forEachIndexed
            for (i in words.indices) {
                val wordEnd = u.startMs + ((i + 1) * MS_PER_WORD)
                val text = words.subList(0, i + 1).joinToString(" ")
                out.add(Timed(wordEnd + partialLagMs, TranscriptUpdate(callId, u.speaker, seg, text, false, u.startMs, wordEnd)))
            }
            val end = u.startMs + words.size * MS_PER_WORD
            out.add(Timed(end + endpointMs, TranscriptUpdate(callId, u.speaker, seg, words.joinToString(" "), true, u.startMs, end)))
        }
        return out.sortedBy { it.emitAtMs }
    }

    companion object {
        /** ~155 words per minute, conversational Indian English. */
        const val MS_PER_WORD = 385L

        fun asrWords(text: String): List<String> =
            text.uppercase().replace(Regex("[^A-Z0-9' ]+"), " ").split(' ').filter { it.isNotBlank() }

        fun durationMs(text: String): Long = asrWords(text).size * MS_PER_WORD
    }
}
