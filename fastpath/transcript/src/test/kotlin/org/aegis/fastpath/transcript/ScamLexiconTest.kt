package org.aegis.fastpath.transcript

import org.aegis.fastpath.event.Qualifier
import org.aegis.fastpath.event.Tactic
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ScamLexiconTest {
    private val lex = ScamLexicon()
    private fun tactics(text: String) = lex.scan(text).map { it.tactic }.toSet()

    @Test
    fun `token matching never fires inside a longer word`() {
        val ac = TokenAhoCorasick(mapOf(listOf("pin") to 1, listOf("any", "desk") to 2))
        assertTrue(ac.scan(listOf("spinning", "pins", "anydesk")).isEmpty())
        assertEquals(listOf(2), ac.scan(listOf("open", "any", "desk")).map { it.value })
    }

    @Test
    fun `a credential request fires, a credential mention does not`() {
        assertTrue(Tactic.CREDENTIAL_REQUEST in tactics("please tell me the OTP you received"))
        assertFalse(Tactic.CREDENTIAL_REQUEST in tactics("you will receive an OTP shortly"))
    }

    @Test
    fun `genuine bank advice is not a request`() {
        assertFalse(Tactic.CREDENTIAL_REQUEST in tactics("SBI will never ask for your OTP, PIN or password"))
        assertFalse(Tactic.CREDENTIAL_REQUEST in tactics("do not share your OTP with anyone"))
        assertFalse(Tactic.REMOTE_ACCESS_REQUEST in tactics("do not install apps like AnyDesk if someone asks"))
    }

    @Test
    fun `dont worry is not a negation and isolation phrases carry their own`() {
        val t = tactics("don't worry sir, install AnyDesk and don't disconnect the call")
        assertTrue(Tactic.REMOTE_ACCESS_REQUEST in t)
        assertTrue(Tactic.ISOLATION in t)
    }

    @Test
    fun `a pin code is an address, not a PIN`() {
        assertFalse(Tactic.CREDENTIAL_REQUEST in tactics("tell me your pin code for delivery"))
    }

    @Test
    fun `a bank name needs a self introduction, police alone is enough`() {
        assertFalse(Tactic.AUTHORITY_CLAIM in tactics("I will go to the SBI branch tomorrow"))
        val bank = lex.scan("I am calling from SBI head office").single { it.tactic == Tactic.AUTHORITY_CLAIM }
        assertEquals(Qualifier.BANK, bank.qualifier)
        assertTrue(Tactic.AUTHORITY_CLAIM in tactics("there is a CBI case against you"))
    }

    @Test
    fun `negated threats do not fire`() {
        assertFalse(Tactic.THREAT in tactics("your account will not be blocked"))
        assertTrue(Tactic.THREAT in tactics("your account will be blocked"))
    }

    @Test
    fun `urgency needs a time unit after within`() {
        assertTrue(Tactic.URGENCY in tactics("it will be frozen within ten minutes"))
        assertFalse(Tactic.URGENCY in tactics("within your account settings"))
    }
}
