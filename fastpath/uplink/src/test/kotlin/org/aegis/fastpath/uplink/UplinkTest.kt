package org.aegis.fastpath.uplink

import org.aegis.fastpath.event.Evidence
import org.aegis.fastpath.event.Qualifier
import org.aegis.fastpath.event.SemanticEvent
import org.aegis.fastpath.event.Tactic
import org.aegis.fastpath.privacy.EgressAuditor
import org.aegis.fastpath.privacy.EventUpdate
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class UplinkTest {
    private val dir: File = Files.createTempDirectory("uplink").toFile()

    private fun event(rev: Int) = EventUpdate(
        SemanticEvent("c1:THREAT:NONE", "c1", rev, Tactic.THREAT, Qualifier.NONE, 0.8, Evidence.COMMITTED,
            "lexicon", 0, 0, 100, 400, 1),
    )

    @Test
    fun `nothing is lost across a dropped network and a restart, and nothing is sent twice`() {
        val journal = File(dir, "j1")
        val received = mutableListOf<String>()
        var online = false
        val transport = UplinkTransport { key, _ -> if (online) received.add(key) else false; online }

        val first = Uplink(EgressJournal(journal), transport, EgressAuditor())
        first.submit(event(1)); first.submit(event(2))
        assertEquals(0, first.pump())
        assertEquals(2, first.pendingCount)

        // The app is killed here. A new process replays the journal.
        online = true
        val second = Uplink(EgressJournal(journal), transport, EgressAuditor())
        assertEquals(2, second.pendingCount)
        assertIs<Uplink.SubmitResult.Duplicate>(second.submit(event(2)))
        assertEquals(2, second.pump())
        assertEquals(listOf("c1:THREAT:NONE#1", "c1:THREAT:NONE#2"), received)

        val third = Uplink(EgressJournal(journal), transport, EgressAuditor())
        assertEquals(0, third.pendingCount)
    }

    @Test
    fun `a torn record at the end of the journal is dropped, earlier ones survive`() {
        val f = File(dir, "j2")
        val j = EgressJournal(f)
        j.appendPayload("a", "{}")
        j.appendPayload("b", "{}")
        f.writeBytes(f.readBytes().copyOf(f.length().toInt() - 5))
        assertEquals(listOf("a"), j.replay().pending.map { it.key })
        j.appendPayload("c", "{}")
        assertEquals(listOf("a", "c"), EgressJournal(f).replay().pending.map { it.key })
    }
}
