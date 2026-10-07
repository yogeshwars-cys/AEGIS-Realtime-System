package org.aegis.fastpath.engine

import org.aegis.fastpath.event.Evidence
import org.aegis.fastpath.event.Qualifier
import org.aegis.fastpath.event.Speaker
import org.aegis.fastpath.event.Tactic
import org.aegis.fastpath.event.Tactic.AUTHORITY_CLAIM
import org.aegis.fastpath.event.Tactic.CREDENTIAL_REQUEST
import org.aegis.fastpath.event.Tactic.ISOLATION
import org.aegis.fastpath.event.Tactic.REMOTE_ACCESS_REQUEST
import org.aegis.fastpath.event.Tactic.THREAT
import org.aegis.fastpath.event.Tactic.URGENCY
import org.aegis.fastpath.observation.CompositeExtractor
import org.aegis.fastpath.observation.ObservedTactic
import org.aegis.fastpath.observation.SegmentObservation
import org.aegis.fastpath.observation.SemanticExtractor
import org.aegis.fastpath.prior.CallerPrior
import org.aegis.fastpath.risk.FrictionStep
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The engine is driven here with observations only: no text, no lexicon. Anything an extractor
 * can express through the contract, these tests can express too.
 */
class FastPathEngineTest {
    private var seg = 0
    private fun engine(prior: CallerPrior = CallerPrior.NONE) = FastPathEngine("c1", prior = prior, clockMs = { 0L })

    private fun obs(vararg t: Tactic, final: Boolean = true, who: Speaker = Speaker.CALLER, segment: Int = seg++, conf: Double = 0.9) =
        SegmentObservation("c1", segment, who, final, 0, 0, t.map { ObservedTactic(it, Qualifier.NONE, conf, "test") })

    private fun FastPathEngine.see(vararg t: Tactic, final: Boolean = true, who: Speaker = Speaker.CALLER, segment: Int = seg++) =
        onObservation(obs(*t, final = final, who = who, segment = segment))

    @Test
    fun `a non-final reading opens a provisional event and the final confirms the same event`() {
        val e = engine()
        val p = e.see(REMOTE_ACCESS_REQUEST, final = false, segment = 7).changedEvents.single()
        assertEquals(Evidence.PROVISIONAL, p.evidence)
        val c = e.see(REMOTE_ACCESS_REQUEST, final = true, segment = 7).changedEvents.single()
        assertEquals(p.eventId, c.eventId)
        assertEquals(Evidence.COMMITTED, c.evidence)
        assertEquals(p.revision + 1, c.revision)
    }

    @Test
    fun `a final that drops a provisional tactic retracts it`() {
        val e = engine()
        e.see(REMOTE_ACCESS_REQUEST, final = false, segment = 3)
        val r = e.see(final = true, segment = 3).changedEvents.single()
        assertEquals(Evidence.RETRACTED, r.evidence)
    }

    @Test
    fun `provisional evidence alone never climbs past a nudge`() {
        val e = engine()
        val t = e.see(ISOLATION, REMOTE_ACCESS_REQUEST, CREDENTIAL_REQUEST, URGENCY, final = false)
        assertEquals(FrictionStep.NUDGE, t.snapshot.step)
    }

    @Test
    fun `an extraction request with no manipulation stops at verify`() {
        val e = engine()
        e.see(AUTHORITY_CLAIM)
        val t = e.see(CREDENTIAL_REQUEST)
        assertEquals(FrictionStep.VERIFY, t.snapshot.step)
        assertEquals(FrictionStep.VERIFY, t.snapshot.ceiling)
    }

    @Test
    fun `the pattern reaches the reality pause`() {
        val e = engine()
        e.see(AUTHORITY_CLAIM)
        e.see(THREAT, URGENCY)
        e.see(ISOLATION)
        val t = e.see(REMOTE_ACCESS_REQUEST)
        assertEquals(FrictionStep.PAUSE, t.snapshot.step)
        assertEquals(listOf(AUTHORITY_CLAIM, THREAT, URGENCY, ISOLATION, REMOTE_ACCESS_REQUEST), t.snapshot.path)
    }

    @Test
    fun `the ladder never steps back down within a call`() {
        val e = engine()
        e.see(THREAT, URGENCY, ISOLATION)
        val reached = e.snapshot().step
        repeat(5) { e.see() }
        assertEquals(reached, e.snapshot().step)
    }

    @Test
    fun `the same tactic ten times scores the same as once`() {
        val once = engine().also { it.see(CREDENTIAL_REQUEST) }.snapshot().score
        val e = engine()
        repeat(10) { e.see(CREDENTIAL_REQUEST) }
        assertEquals(once, e.snapshot().score, 1e-9)
    }

    @Test
    fun `victim observations never produce events`() {
        val t = engine().see(CREDENTIAL_REQUEST, REMOTE_ACCESS_REQUEST, who = Speaker.VICTIM)
        assertTrue(t.changedEvents.isEmpty())
    }

    @Test
    fun `a reputation prior alone cannot authorise more than a nudge`() {
        val t = engine(prior = CallerPrior(1.0, listOf("fri"))).see()
        assertEquals(FrictionStep.NUDGE, t.snapshot.step)
    }

    @Test
    fun `observations for a finalised segment or another call are dropped and counted`() {
        val e = engine()
        e.see(THREAT, segment = 1)
        assertTrue(e.see(REMOTE_ACCESS_REQUEST, final = false, segment = 1).changedEvents.isEmpty())
        assertTrue(e.onObservation(obs(THREAT).copy(callId = "other")).changedEvents.isEmpty())
        assertEquals(2, e.contractViolations)
    }

    @Test
    fun `the user flag goes straight to verify`() {
        assertEquals(FrictionStep.VERIFY, engine().userFlagged().snapshot.step)
    }

    @Test
    fun `composite merges extractors by strongest confidence and survives one failing`() {
        val weak = SemanticExtractor<Int> { obs(THREAT, segment = it, conf = 0.4) }
        val strong = SemanticExtractor<Int> { obs(THREAT, ISOLATION, segment = it, conf = 0.95) }
        val broken = SemanticExtractor<Int> { error("model not loaded") }
        val c = CompositeExtractor(listOf(weak, broken, strong))
        val merged = c.extract(5)
        assertEquals(setOf(THREAT, ISOLATION), merged.tactics.map { it.tactic }.toSet())
        assertEquals(0.95, merged.tactics.first { it.tactic == THREAT }.confidence)
        assertEquals(1, c.failures)
    }

    @Test
    fun `the contract rejects malformed observations at construction`() {
        assertFailsWith<IllegalArgumentException> { ObservedTactic(THREAT, confidence = 1.5, source = "x") }
        assertFailsWith<IllegalArgumentException> { ObservedTactic(THREAT, confidence = 0.5, source = "has space") }
        assertFailsWith<IllegalArgumentException> { obs(THREAT, THREAT) }
    }
}
