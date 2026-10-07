package org.aegis.fastpath.uplink

import org.aegis.fastpath.privacy.EgressAuditor
import org.aegis.fastpath.privacy.EgressPayload
import org.aegis.fastpath.util.Json
import java.io.File

/**
 * Sends one payload. Returns true only when the receiver has it (acknowledged), false to retry
 * later. Must not throw for ordinary network failures; the uplink treats a throw as false.
 */
fun interface UplinkTransport {
    fun send(key: String, json: String): Boolean
}

/**
 * The phone's only way out, and it sits strictly downstream of inference.
 *
 * Order of operations for every payload: audit (an [EgressAuditor] rescan, a failure is
 * blocked and never written anywhere) -> dedupe by idempotency key -> journal + fsync -> send.
 * Sending is a separate [pump] so the fast path never waits on the network: on the phone the
 * pump runs on its own IO thread, in replay it is called after each tick.
 *
 * Sends stop at the first failure to preserve order (a deep path that sees revision 3 of an
 * event before revision 2 has to reason about it). Recovery is replay of the journal.
 */
class Uplink(
    private val journal: EgressJournal,
    private val transport: UplinkTransport,
    private val auditor: EgressAuditor,
) {
    sealed interface SubmitResult {
        data object Queued : SubmitResult
        data object Duplicate : SubmitResult
        data class Blocked(val violations: List<String>) : SubmitResult
    }

    private val pending = ArrayDeque<EgressJournal.Pending>()
    private val seen = HashSet<String>()

    var submitted = 0; private set
    var duplicates = 0; private set
    var blocked = 0; private set
    var sent = 0; private set
    var sendFailures = 0; private set
    val pendingCount: Int get() = pending.size

    init {
        val replay = journal.replay()
        seen += replay.seenKeys
        pending += replay.pending
    }

    fun submit(payload: EgressPayload): SubmitResult {
        val verdict = auditor.check(payload)
        if (!verdict.ok) {
            blocked++
            return SubmitResult.Blocked(verdict.violations)
        }
        val key = payload.idempotencyKey
        if (!seen.add(key)) {
            duplicates++
            return SubmitResult.Duplicate
        }
        val json = payload.toJson()
        journal.appendPayload(key, json)
        pending.addLast(EgressJournal.Pending(key, json))
        submitted++
        return SubmitResult.Queued
    }

    /** Try to send what is pending, in order. Returns how many were acknowledged. */
    fun pump(max: Int = Int.MAX_VALUE): Int {
        var n = 0
        while (n < max && pending.isNotEmpty()) {
            val next = pending.first()
            val ok = try { transport.send(next.key, next.json) } catch (t: Throwable) { false }
            if (!ok) { sendFailures++; break }
            journal.appendAck(next.key)
            pending.removeFirst()
            sent++
            n++
        }
        return n
    }
}

/** Appends each payload as one JSON line. The demo's stand-in for the network, and its egress log. */
class JsonlFileTransport(private val file: File) : UplinkTransport {
    init {
        file.parentFile?.mkdirs()
    }

    override fun send(key: String, json: String): Boolean {
        file.appendText("{" + Json.str("key") + ":" + Json.str(key) + "," + Json.str("payload") + ":" + json + "}\n")
        return true
    }
}
