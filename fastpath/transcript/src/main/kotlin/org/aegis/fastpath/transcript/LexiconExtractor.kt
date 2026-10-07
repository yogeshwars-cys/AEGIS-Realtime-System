package org.aegis.fastpath.transcript

import org.aegis.fastpath.event.Qualifier
import org.aegis.fastpath.event.Speaker
import org.aegis.fastpath.event.Tactic
import org.aegis.fastpath.observation.ObservedTactic
import org.aegis.fastpath.observation.SegmentObservation
import org.aegis.fastpath.observation.SemanticExtractor

/** One tactic the lexicon found in one piece of text. Internal to the text layer. */
data class TacticHit(
    val tactic: Tactic,
    val qualifier: Qualifier,
    val confidence: Double,
    /** Token span inside the scanned text, for explanation and tests. Never transmitted. */
    val tokenStart: Int = 0,
    val tokenEnd: Int = 0,
)

/**
 * The baseline extractor: [ScamLexicon] over transcript updates, partials included.
 *
 * This is one implementation of [SemanticExtractor], not part of the engine. A trained text
 * tagger implements `SemanticExtractor<TranscriptUpdate>` the same way and either replaces this
 * or runs beside it in a [org.aegis.fastpath.observation.CompositeExtractor].
 *
 * Victim updates come back with no tactics: there is no point scanning words the engine will
 * ignore.
 */
class LexiconExtractor(private val lexicon: ScamLexicon = ScamLexicon()) : SemanticExtractor<TranscriptUpdate> {

    override fun extract(input: TranscriptUpdate): SegmentObservation {
        val tactics = if (input.speaker == Speaker.VICTIM) emptyList() else
            lexicon.scan(input.text).map { ObservedTactic(it.tactic, it.qualifier, it.confidence, SOURCE) }
        return SegmentObservation(
            callId = input.callId,
            segmentId = input.segmentId,
            speaker = input.speaker,
            isFinal = input.isFinal,
            audioStartMs = input.audioStartMs,
            audioEndMs = input.audioEndMs,
            tactics = tactics,
        )
    }

    companion object {
        const val SOURCE = "lexicon"
    }
}
