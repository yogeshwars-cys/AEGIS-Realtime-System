package org.aegis.fastpath.uplink

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/**
 * Write-ahead journal for payloads waiting to leave the phone.
 *
 * Every payload is appended and fsynced **before** the uplink tries to send it, so a crash, a
 * killed app or a dropped network loses nothing: on restart [replay] returns what was never
 * acknowledged and the uplink resends it. Each record is framed (magic, body length, SHA-256 of
 * the body), so a record torn by a crash fails its checksum and the tail is truncated rather
 * than parsed. Idempotent: a key appended twice counts once.
 *
 * Body layout (no JSON parser needed on the read path):
 * `kind:u8 | keyLen:i32 | key | jsonLen:i32 | json`, kind 1 = payload, 2 = ack.
 */
class EgressJournal(private val file: File, private val durable: Boolean = true) {

    data class Pending(val key: String, val json: String)

    data class Replay(val pending: List<Pending>, val seenKeys: Set<String>)

    init {
        file.parentFile?.mkdirs()
    }

    fun appendPayload(key: String, json: String) = append(frame(KIND_PAYLOAD, key, json))

    fun appendAck(key: String) = append(frame(KIND_ACK, key, ""))

    /** Unacknowledged payloads in append order, first occurrence per key. Repairs a torn tail. */
    fun replay(): Replay {
        if (!file.exists()) return Replay(emptyList(), emptySet())
        val data = file.readBytes()
        val payloads = LinkedHashMap<String, String>()
        val acked = HashSet<String>()
        var offset = 0
        while (offset + HEADER <= data.size) {
            val buf = ByteBuffer.wrap(data, offset, HEADER)
            val magic = ByteArray(4).also { buf.get(it) }
            val length = buf.int
            val checksum = ByteArray(32).also { buf.get(it) }
            if (!magic.contentEquals(MAGIC) || length < 0 || offset + HEADER + length > data.size) break
            val body = data.copyOfRange(offset + HEADER, offset + HEADER + length)
            if (!sha256(body).contentEquals(checksum)) break
            val b = ByteBuffer.wrap(body)
            val kind = b.get().toInt()
            val key = String(ByteArray(b.int).also { b.get(it) }, Charsets.UTF_8)
            val json = String(ByteArray(b.int).also { b.get(it) }, Charsets.UTF_8)
            when (kind) {
                KIND_PAYLOAD.toInt() -> payloads.putIfAbsent(key, json)
                KIND_ACK.toInt() -> acked.add(key)
            }
            offset += HEADER + length
        }
        if (offset < data.size) {
            // Drop the torn tail so new appends follow good records.
            FileOutputStream(file, true).channel.use { it.truncate(offset.toLong()) }
        }
        val pending = payloads.filterKeys { it !in acked }.map { (k, v) -> Pending(k, v) }
        return Replay(pending, payloads.keys)
    }

    /** Rewrite the journal with only what is still unacknowledged. Atomic replace. */
    fun compact() {
        val keep = replay().pending
        val tmp = File(file.path + ".compact")
        FileOutputStream(tmp).use { out ->
            for (p in keep) out.write(frame(KIND_PAYLOAD, p.key, p.json))
            out.flush()
            if (durable) out.fd.sync()
        }
        Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    }

    private fun append(bytes: ByteArray) {
        FileOutputStream(file, true).use { out ->
            out.write(bytes)
            out.flush()
            if (durable) out.fd.sync()
        }
    }

    private fun frame(kind: Byte, key: String, json: String): ByteArray {
        val bodyStream = ByteArrayOutputStream()
        DataOutputStream(bodyStream).use { d ->
            val k = key.toByteArray(Charsets.UTF_8)
            val j = json.toByteArray(Charsets.UTF_8)
            d.writeByte(kind.toInt())
            d.writeInt(k.size); d.write(k)
            d.writeInt(j.size); d.write(j)
        }
        val body = bodyStream.toByteArray()
        return ByteBuffer.allocate(HEADER + body.size)
            .put(MAGIC).putInt(body.size).put(sha256(body)).put(body)
            .array()
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private companion object {
        val MAGIC = "AEJ1".toByteArray(Charsets.US_ASCII)
        const val HEADER = 4 + 4 + 32
        const val KIND_PAYLOAD: Byte = 1
        const val KIND_ACK: Byte = 2
    }
}
