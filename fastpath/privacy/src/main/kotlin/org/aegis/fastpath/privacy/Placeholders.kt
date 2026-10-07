package org.aegis.fastpath.privacy

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Keyed 64-bit digest of a caller-side identifier.
 *
 * Threat model, stated rather than implied: a salted hash is
 * pseudonymity, not privacy. Anyone holding the salt can confirm a guess, and phone numbers live
 * in a space small enough to enumerate. It is used only for *caller* identifiers (the UPI handle
 * a scammer asks the victim to pay, the number they ask for a call back on, the alias they use),
 * so incidents can be linked across victims. Victim identifiers are never hashed, only replaced.
 * HMAC-SHA256 instead of blake2b because javax.crypto has it on both the JVM and Android.
 */
class SaltedHasher(salt: ByteArray) {
    private val key = SecretKeySpec(salt.copyOf(), "HmacSHA256")

    init {
        require(salt.size >= 16) { "salt must be at least 16 bytes" }
    }

    fun hash(namespace: String, value: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        val digest = mac.doFinal("$namespace:$value".toByteArray(Charsets.UTF_8))
        return digest.take(8).joinToString("") { "%02x".format(it) }
    }
}

/**
 * Per-call placeholder assignment. The same person is the same placeholder for the whole call
 * ("[PERSON_1]" every time), so the deep path keeps coreference without ever seeing the name.
 */
class PlaceholderRegistry(private val hasher: SaltedHasher) {
    private val numbering = HashMap<PiiType, HashMap<String, Int>>()

    fun render(span: PiiSpan): String {
        val type = span.type
        if (type.hashedWhenCallers && span.owner == Owner.CALLER && span.value.isNotEmpty()) {
            val label = if (type == PiiType.CALLER_ALIAS) type.label else "CALLER_${type.label}"
            return "[$label#${hasher.hash(type.label.lowercase(), span.value)}]"
        }
        return when (type) {
            PiiType.PERSON, PiiType.CALLER_ALIAS -> {
                val ids = numbering.getOrPut(PiiType.PERSON) { HashMap() }
                val n = ids.getOrPut(span.value) { ids.size + 1 }
                "[PERSON_$n]"
            }
            // Magnitude only: "fifty thousand" -> [AMOUNT~1e4]. Useful to reasoning, identifies nobody.
            PiiType.AMOUNT -> "[AMOUNT~1e${maxOf(0, span.value.trimStart('0').length - 1)}]"
            else -> "[${type.label}]"
        }
    }
}
