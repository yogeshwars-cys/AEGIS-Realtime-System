package org.aegis.fastpath.transcript

import org.aegis.fastpath.event.Speaker
import org.aegis.fastpath.event.Tactic
import org.aegis.fastpath.observation.ObservationCodec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class LexiconExtractorTest {
    private val x = LexiconExtractor()

    @Test
    fun `transcript updates become contract observations`() {
        val obs = x.extract(TranscriptUpdate("c1", Speaker.CALLER, 4, "please don't disconnect the call", true, 1000, 2500))
        assertEquals(4, obs.segmentId)
        assertTrue(obs.isFinal)
        assertEquals(listOf(Tactic.ISOLATION), obs.tactics.map { it.tactic })
        assertEquals(LexiconExtractor.SOURCE, obs.tactics.single().source)
    }

    @Test
    fun `victim speech yields an observation with no tactics`() {
        val obs = x.extract(TranscriptUpdate("c1", Speaker.VICTIM, 5, "should I tell you the OTP", true, 0, 0))
        assertTrue(obs.tactics.isEmpty())
    }

    @Test
    fun `observations survive the wire format unchanged`() {
        val obs = x.extract(TranscriptUpdate("c1", Speaker.CALLER, 2, "I am calling from SBI, install AnyDesk now", false, 300, 2900))
        val back = ObservationCodec.decode(ObservationCodec.encode(obs, emitAtMs = 3200))
        assertEquals(3200, back.emitAtMs)
        assertEquals(obs.copy(tactics = obs.tactics.map { it.copy(confidence = it.confidence) }), back.observation)
    }
}
