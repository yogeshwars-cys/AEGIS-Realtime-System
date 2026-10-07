package org.aegis.fastpath.transcript

import org.aegis.fastpath.event.Speaker

/** What the speech recogniser hands the text layer. Partials carry the full hypothesis so far. */
data class TranscriptUpdate(
    val callId: String,
    val speaker: Speaker,
    val segmentId: Int,
    val text: String,
    val isFinal: Boolean,
    val audioStartMs: Long,
    val audioEndMs: Long,
)
