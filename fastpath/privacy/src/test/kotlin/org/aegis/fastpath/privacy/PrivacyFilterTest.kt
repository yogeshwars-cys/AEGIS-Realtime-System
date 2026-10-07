package org.aegis.fastpath.privacy

import org.aegis.fastpath.event.Speaker
import org.aegis.fastpath.transcript.TranscriptUpdate
import org.aegis.fastpath.transcript.ScamLexicon
import org.aegis.fastpath.transcript.TextNormalizer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PrivacyFilterTest {
    private val salt = ByteArray(32) { it.toByte() }
    private val vocab = ScamLexicon().vocabulary
    private val detector = PiiDetector(vocab)
    private val auditor = EgressAuditor()

    private fun spans(text: String, who: Speaker = Speaker.VICTIM) = detector.detect(TextNormalizer.tokens(text), who)

    private fun commit(f: PrivacyFilter, text: String, who: Speaker = Speaker.VICTIM, t: Long = 0) =
        f.onCommit(TranscriptUpdate("c1", who, 0, text, true, t, t + 1000))

    @Test
    fun `spoken digits are recovered`() {
        fun digits(s: String) = SpokenNumbers.runs(TextNormalizer.tokens(s)).single().digits
        assertEquals("4821", digits("four eight two one"))
        assertEquals("4821", digits("forty eight twenty one"))
        assertEquals("9955", digits("double nine double five"))
        assertEquals("50000", digits("fifty thousand"))
        assertEquals("402", digits("four hundred two"))
    }

    @Test
    fun `numbers are typed by context and shape`() {
        assertEquals(PiiType.ACCT_LAST4, spans("account ending four eight two one").single().type)
        assertEquals(PiiType.OTP, spans("the otp is seven three one nine").single().type)
        assertEquals(PiiType.AADHAAR, spans("four eight two one seven three three zero one two nine zero").single().type)
        assertEquals(PiiType.PHONE, spans("nine eight seven six five four three two one zero").single().type)
    }

    @Test
    fun `short numbers carry urgency and survive`() {
        assertTrue(spans("it will be frozen within ten minutes").isEmpty())
        assertTrue(spans("between two and four in the afternoon").isEmpty())
    }

    @Test
    fun `an organisation is never mistaken for a name`() {
        assertTrue(spans("this is SBI calling", Speaker.CALLER).isEmpty())
        assertTrue(spans("this is confidential", Speaker.CALLER).isEmpty())
    }

    @Test
    fun `who an identifier belongs to decides hash versus placeholder`() {
        val f = PrivacyFilter("c1", salt, vocab)
        val caller = commit(f, "send it to the upi id cybercell at ybl.", Speaker.CALLER).single().text
        assertTrue(Regex("\\[CALLER_UPI#[0-9a-f]{16}]").containsMatchIn(caller), caller)
        val g = PrivacyFilter("c2", salt, vocab)
        val victim = commit(g, "my upi id is ravi at okaxis.", Speaker.VICTIM).single().text
        assertTrue("[UPI]" in victim, victim)
    }

    @Test
    fun `the same person keeps the same placeholder`() {
        val f = PrivacyFilter("c1", salt, vocab)
        val a = commit(f, "hello ravindra kumar.", Speaker.CALLER).single().text
        val b = commit(f, "ravindra kumar please listen.", Speaker.CALLER, 2000).single().text
        assertTrue("[PERSON_1]" in a && "[PERSON_1]" in b, "$a / $b")
    }

    @Test
    fun `a number split across two commits is redacted as one`() {
        val f = PrivacyFilter("c1", salt, vocab)
        assertTrue(commit(f, "it is four eight two one seven three three").isEmpty(), "tail must be held")
        // Still a number at the tail: it might go on, so both commits stay on the phone...
        assertTrue(commit(f, "zero one two nine zero", t = 3000).isEmpty())
        // ...until the speaker has been quiet for the hold window. Then it leaves as one span.
        assertEquals("it is [AADHAAR]", f.flushStale(6000).single().text)
    }

    @Test
    fun `held text is released after the speaker goes quiet`() {
        val f = PrivacyFilter("c1", salt, vocab, holdMs = 1500)
        commit(f, "my otp is seven three")
        assertTrue(f.flushStale(1500).isEmpty())
        val out = f.flushStale(2600).single().text
        assertFalse(auditor.checkText(out).violations.isNotEmpty(), out)
    }

    @Test
    fun `the auditor catches what the filter should have removed`() {
        val a = EgressAuditor(listOf("Ravindra Kumar"))
        assertFalse(a.checkText("call me on 9876543210").ok)
        assertFalse(a.checkText("it is four eight two one").ok)
        assertFalse(a.checkText("hello ravindra kumar").ok)
        assertFalse(a.checkText("pay to ravi@okaxis").ok)
        assertTrue(a.checkText("hello [PERSON_1] pay to [CALLER_UPI#0123456789abcdef] within ten minutes").ok)
    }
}
