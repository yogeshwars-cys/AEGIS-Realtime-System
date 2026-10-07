package org.aegis.fastpath.privacy

import org.aegis.fastpath.event.Speaker
import org.aegis.fastpath.transcript.TranscriptUpdate
import org.aegis.fastpath.transcript.TextNormalizer

/** Running totals for the privacy report. */
class PrivacyStats {
    val removedByType = HashMap<PiiType, Int>()
    var segmentsEmitted = 0
        internal set
    var segmentsDropped = 0
        internal set
    var holdbacks = 0
        internal set
    var timeoutFlushes = 0
        internal set
    val spansRemoved: Int get() = removedByType.values.sum()
}

/**
 * The on-device filter between the transcript and anything that leaves the phone.
 *
 * Runs only on **committed** ASR text: partials are unstable and never leave. Three properties
 * matter more than detector recall:
 *
 *  1. **Holdback.** PII is often split across commits ("my Aadhaar is four eight two one" /
 *     "seven seven three zero..."). A per-speaker redactor holds a commit back whole when its
 *     tail could start a sensitive span (a number word, "my name is", "at") and redacts it
 *     together with the next commit, or once the speaker has been silent for [holdMs]. This
 *     delays only the deep path; the fast path never waits on this filter.
 *  2. **Fail closed.** If anything throws, the segment is dropped and only events leave.
 *  3. **Speaker-aware ownership.** On a two-channel call the channel says who spoke, which
 *     decides whether an identifier is the victim's (replaced) or the caller's (salted hash for
 *     cross-incident linking).
 */
class PrivacyFilter(
    private val callId: String,
    salt: ByteArray,
    protectedVocabulary: Set<String> = emptySet(),
    private val holdMs: Long = 1_500,
) {
    private val detector = PiiDetector(protectedVocabulary)
    private val registry = PlaceholderRegistry(SaltedHasher(salt))
    private val redactors = HashMap<Speaker, SpeakerRedactor>()
    val stats = PrivacyStats()

    fun onCommit(update: TranscriptUpdate): List<RedactedSegment> {
        require(update.isFinal) { "only committed text goes through the privacy filter" }
        val r = redactor(update.speaker)
        r.lastActivityMs = update.audioEndMs
        return guarded(r) { r.accept(TextNormalizer.tokens(update.text), update.audioStartMs, update.audioEndMs, false) }
    }

    /**
     * A partial from this speaker: they are still talking, so a held tail may be about to
     * continue. Partials themselves never pass through the filter and never leave.
     */
    fun notePartial(update: TranscriptUpdate) {
        redactor(update.speaker).lastActivityMs = update.audioEndMs
    }

    /**
     * Release held tokens once their speaker has been silent for [holdMs] of audio time.
     * Call on a timer or on every tick.
     */
    fun flushStale(nowMs: Long): List<RedactedSegment> =
        redactors.values.flatMap { r ->
            val since = r.pendingSince
            if (since != null && nowMs - maxOf(since, r.lastActivityMs) >= holdMs) {
                stats.timeoutFlushes++
                guarded(r) { r.accept(emptyList(), since, nowMs, true) }
            } else emptyList()
        }

    private fun redactor(speaker: Speaker) = redactors.getOrPut(speaker) { SpeakerRedactor(speaker) }

    /** End of call: release everything. */
    fun flush(nowMs: Long): List<RedactedSegment> =
        redactors.values.flatMap { r -> if (r.pendingSince != null) guarded(r) { r.accept(emptyList(), r.pendingSince!!, nowMs, true) } else emptyList() }

    private fun guarded(r: SpeakerRedactor, block: () -> List<RedactedSegment>): List<RedactedSegment> = try {
        block().also { stats.segmentsEmitted += it.size }
    } catch (t: Throwable) {
        r.reset()
        stats.segmentsDropped++
        emptyList()
    }

    private inner class SpeakerRedactor(private val speaker: Speaker) {
        private var pending: List<String> = emptyList()
        var pendingSince: Long? = null
            private set
        var lastActivityMs: Long = 0
        private var seq = 0

        fun reset() { pending = emptyList(); pendingSince = null }

        fun accept(newTokens: List<String>, audioStartMs: Long, audioEndMs: Long, releaseAll: Boolean): List<RedactedSegment> {
            val boundary = pending.size
            val tokens = pending + newTokens
            val startMs = pendingSince ?: audioStartMs
            if (tokens.isEmpty()) { reset(); return emptyList() }

            val spans = detector.detect(tokens, speaker)
            // Hold the newest commit whole when its tail could continue into the next one.
            // Whole segments, not fragments: the deep path reasons over sentences.
            var cut = if (releaseAll || !openTail(tokens)) tokens.size else boundary
            // Never cut through a detected span. A span reaching back into held text means the
            // held text and this commit belong together: keep all of it.
            for (s in spans) if (s.start < cut && s.endExclusive > cut) cut = if (s.start < boundary) 0 else s.start

            val heldFrom = if (cut < boundary) (pendingSince ?: audioStartMs) else audioStartMs
            pending = tokens.subList(cut, tokens.size).toList()
            pendingSince = if (pending.isEmpty()) null else heldFrom
            if (pending.isNotEmpty() && !releaseAll) stats.holdbacks++
            if (cut == 0) return emptyList()

            val out = StringBuilder()
            val removed = HashMap<PiiType, Int>()
            var i = 0
            for (s in spans.filter { it.endExclusive <= cut }.sortedBy { it.start }) {
                while (i < s.start) { out.append(tokens[i]).append(' '); i++ }
                out.append(registry.render(s)).append(' ')
                removed.merge(s.type, 1, Int::plus)
                stats.removedByType.merge(s.type, 1, Int::plus)
                i = s.endExclusive
            }
            while (i < cut) { out.append(tokens[i]).append(' '); i++ }

            return listOf(
                RedactedSegment(callId, speaker, ++seq, out.toString().trim(), startMs, audioEndMs, removed),
            )
        }

        /**
         * Could this commit's end be the start of a span that continues in the next one? A number
         * word anywhere in the last few tokens, or an opener ("is", "my", "at") as the very last.
         */
        private fun openTail(tokens: List<String>): Boolean =
            tokens.takeLast(TAIL).any { SpokenNumbers.isNumberish(it) } || tokens.lastOrNull() in OPEN_TAIL
    }

    private companion object {
        const val TAIL = 3
        val OPEN_TAIL = setOf(
            "is", "my", "name", "number", "at", "otp", "account", "aadhaar", "aadhar", "ending", "last", "code",
            "pin", "dot", "rate", "mr", "mrs", "ms", "this", "am", "im", "upi", "id", "card", "phone", "mobile",
            "address", "flat", "house", "born", "birth", "hello", "hi", "dear", "inspector", "officer",
        )
    }
}
