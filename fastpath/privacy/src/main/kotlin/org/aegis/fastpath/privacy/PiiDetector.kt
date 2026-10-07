package org.aegis.fastpath.privacy

import org.aegis.fastpath.event.Speaker

/**
 * Finds sensitive spans in one normalised token list. Deterministic, no model, a few
 * microseconds per segment.
 *
 * The bias is deliberately toward over-redaction: every run of three or more digits is
 * redacted whatever it turns out to be, so an unrecognised number format costs the deep path a
 * little context instead of leaking. Short numbers survive ("ten minutes", "between two and
 * four") because the urgency in them is the signal.
 *
 * Organisation names are never treated as names ("this is SBI"): the claim to be the bank is the
 * evidence, and it identifies nobody.
 */
class PiiDetector(
    /** Words the scam lexicon uses; none of them is ever taken for a person's name. */
    private val protectedVocabulary: Set<String> = emptySet(),
) {

    fun detect(tokens: List<String>, speaker: Speaker): List<PiiSpan> {
        val spans = mutableListOf<PiiSpan>()
        val other = when (speaker) {
            Speaker.CALLER -> Owner.VICTIM
            Speaker.VICTIM -> Owner.CALLER
            Speaker.UNKNOWN -> Owner.UNKNOWN
        }
        val self = when (speaker) {
            Speaker.CALLER -> Owner.CALLER
            Speaker.VICTIM -> Owner.VICTIM
            Speaker.UNKNOWN -> Owner.UNKNOWN
        }
        fun ctx(start: Int, n: Int = 4): List<String> = tokens.subList(maxOf(0, start - n), start)
        fun ownerByPronoun(start: Int): Owner {
            val c = ctx(start, 5)
            return when {
                "your" in c -> other
                "my" in c || "our" in c -> self
                else -> self
            }
        }

        // Numbers, read out digit by digit or as cardinals.
        for (run in SpokenNumbers.runs(tokens)) {
            val type = classifyNumber(tokens, run) ?: continue
            val owner = if (type.hashedWhenCallers) ownerByPronoun(run.start) else other
            spans.add(PiiSpan(run.start, run.endExclusive, type, owner, run.digits))
        }

        tokens.forEachIndexed { i, t ->
            // PAN, if the recogniser joined it into one token.
            if (PAN.matches(t)) spans.add(PiiSpan(i, i + 1, PiiType.PAN, other, t))
            // Literal handles.
            if ('@' in t) {
                val domain = t.substringAfter('@')
                val type = if ('.' in domain || domain in EMAIL_PROVIDERS) PiiType.EMAIL else PiiType.UPI
                spans.add(PiiSpan(i, i + 1, type, if (type == PiiType.UPI) ownerByPronoun(i) else other, t))
            }
        }

        // Spoken handles: "ravi at okaxis", "ravi at the rate ybl", "ravi at gmail dot com".
        tokens.forEachIndexed { i, t ->
            if (t != "at" || i == 0) return@forEachIndexed
            val j = if (tokens.getOrNull(i + 1) == "the" && tokens.getOrNull(i + 2) == "rate") i + 3 else i + 1
            val host = tokens.getOrNull(j) ?: return@forEachIndexed
            val handle = tokens[i - 1]
            when {
                host in PSP_HANDLES -> spans.add(
                    PiiSpan(i - 1, j + 1, PiiType.UPI, ownerByPronoun(i - 1), "$handle@$host"),
                )
                host in EMAIL_PROVIDERS || tokens.getOrNull(j + 1) == "dot" -> {
                    val end = if (tokens.getOrNull(j + 1) == "dot") minOf(tokens.size, j + 3) else j + 1
                    spans.add(PiiSpan(i - 1, end, PiiType.EMAIL, other, "$handle@$host"))
                }
            }
        }

        // Names after an introduction or a form of address.
        for ((trigger, isSelf) in NAME_TRIGGERS) {
            var from = 0
            while (true) {
                val at = indexOfSequence(tokens, trigger, from)
                if (at < 0) break
                from = at + 1
                var k = at + trigger.size
                while (k < tokens.size && tokens[k] in TITLES) k++
                val nameStart = k
                while (k < tokens.size && k - nameStart < 2 && looksLikeName(tokens[k])) k++
                if (k > nameStart) {
                    val owner = if (isSelf) self else other
                    val type = if (owner == Owner.CALLER) PiiType.CALLER_ALIAS else PiiType.PERSON
                    spans.add(PiiSpan(nameStart, k, type, owner, tokens.subList(nameStart, k).joinToString(" ")))
                }
            }
        }
        // Names with no introduction, from the gazetteer: always treated as the victim's side.
        tokens.forEachIndexed { i, t ->
            if (t in FIRST_NAMES && t !in protectedVocabulary) {
                val end = if (tokens.getOrNull(i + 1)?.let { it in SURNAMES } == true) i + 2 else i + 1
                spans.add(PiiSpan(i, end, PiiType.PERSON, other, tokens.subList(i, end).joinToString(" ")))
            }
        }

        // Addresses and dates of birth: redact a window, fail closed.
        tokens.forEachIndexed { i, t ->
            if (t in ADDRESS_TRIGGERS) {
                spans.add(PiiSpan(maxOf(0, i - 2), minOf(tokens.size, i + 4), PiiType.ADDRESS, other, ""))
            }
        }
        for (trigger in DOB_TRIGGERS) {
            val at = indexOfSequence(tokens, trigger, 0)
            if (at >= 0) {
                val s = at + trigger.size
                if (s < tokens.size) spans.add(PiiSpan(s, minOf(tokens.size, s + 5), PiiType.DOB, other, ""))
            }
        }

        return merge(spans)
    }

    private fun looksLikeName(t: String): Boolean =
        t.length >= 2 && t.all { it.isLetter() } && t !in STOP && t !in protectedVocabulary &&
            !SpokenNumbers.isNumberish(t)

    private fun classifyNumber(tokens: List<String>, run: SpokenNumbers.Run): PiiType? {
        val d = run.digits
        val len = d.length
        val before = tokens.subList(maxOf(0, run.start - 4), run.start)
        val after = tokens.getOrNull(run.endExclusive)
        val beforeJoined = before.joinToString(" ")

        if ("pin code" in beforeJoined || "pincode" in before) return PiiType.ADDRESS
        if (after in AMOUNT_AFTER || before.lastOrNull() in AMOUNT_BEFORE || (run.cardinal && len >= 4)) {
            return PiiType.AMOUNT
        }
        if (len < 3) return null
        return when {
            before.any { it in OTP_CONTEXT } && len <= 8 -> PiiType.OTP
            before.any { it in LAST4_CONTEXT } && len <= 6 -> PiiType.ACCT_LAST4
            before.any { it in AADHAAR_CONTEXT } -> PiiType.AADHAAR
            before.any { it == "card" } -> PiiType.CARD
            before.any { it in ACCOUNT_CONTEXT } -> PiiType.ACCOUNT
            before.any { it in PHONE_CONTEXT } && len in 10..12 -> PiiType.PHONE
            len == 10 && d[0] in '6'..'9' -> PiiType.PHONE
            len == 12 && d.startsWith("91") && d[2] in '6'..'9' -> PiiType.PHONE
            len == 12 -> PiiType.AADHAAR
            len in 13..19 && luhn(d) -> PiiType.CARD
            len in 9..18 -> PiiType.ACCOUNT
            else -> PiiType.NUMBER
        }
    }

    private fun merge(spans: List<PiiSpan>): List<PiiSpan> {
        if (spans.isEmpty()) return spans
        val sorted = spans.sortedWith(compareBy({ it.start }, { -it.endExclusive }))
        val out = mutableListOf(sorted.first())
        for (s in sorted.drop(1)) {
            val last = out.last()
            if (s.start < last.endExclusive) {
                // Overlap: keep the union, typed by whichever span is more specific.
                val keep = if (rank(s.type) < rank(last.type)) s else last
                out[out.size - 1] = keep.copy(start = last.start, endExclusive = maxOf(last.endExclusive, s.endExclusive))
            } else {
                out.add(s)
            }
        }
        return out
    }

    private fun rank(t: PiiType): Int = when (t) {
        PiiType.AADHAAR, PiiType.PAN, PiiType.CARD, PiiType.OTP -> 0
        PiiType.UPI, PiiType.EMAIL, PiiType.PHONE, PiiType.ACCOUNT, PiiType.ACCT_LAST4 -> 1
        PiiType.PERSON, PiiType.CALLER_ALIAS, PiiType.DOB, PiiType.ADDRESS -> 2
        PiiType.NUMBER, PiiType.AMOUNT -> 3
    }

    companion object {
        private val PAN = Regex("[a-z]{5}[0-9]{4}[a-z]")

        fun luhn(d: String): Boolean {
            var sum = 0
            d.reversed().forEachIndexed { i, c ->
                var v = c - '0'
                if (i % 2 == 1) { v *= 2; if (v > 9) v -= 9 }
                sum += v
            }
            return sum % 10 == 0
        }

        fun indexOfSequence(tokens: List<String>, seq: List<String>, from: Int): Int {
            if (seq.isEmpty()) return -1
            for (i in from..tokens.size - seq.size) {
                if ((seq.indices).all { tokens[i + it] == seq[it] }) return i
            }
            return -1
        }

        val OTP_CONTEXT = setOf("otp", "code", "pin", "cvv", "mpin", "password")
        val LAST4_CONTEXT = setOf("ending", "last", "ends", "ends with")
        val AADHAAR_CONTEXT = setOf("aadhaar", "aadhar", "adhaar", "uid")
        val ACCOUNT_CONTEXT = setOf("account", "acc", "ac", "ifsc")
        val PHONE_CONTEXT = setOf("phone", "mobile", "number", "call", "whatsapp", "contact")
        val AMOUNT_AFTER = setOf("rupees", "rupee", "rs", "inr", "only")
        val AMOUNT_BEFORE = setOf("rs", "inr", "rupees")

        val PSP_HANDLES = setOf(
            "ybl", "okaxis", "okicici", "oksbi", "okhdfcbank", "paytm", "ibl", "axl", "apl", "upi",
            "ptyes", "ptaxis", "pthdfc", "ptsbi", "fbl", "ikwik", "freecharge", "axisbank", "hdfcbank",
        )
        val EMAIL_PROVIDERS = setOf("gmail", "yahoo", "outlook", "hotmail", "rediffmail", "icloud", "protonmail")

        /** Introduction triggers. `true` = the speaker names themself. */
        val NAME_TRIGGERS: List<Pair<List<String>, Boolean>> = listOf(
            listOf("my", "name", "is") to true, listOf("name", "is") to true, listOf("this", "is") to true,
            listOf("i", "am") to true, listOf("im") to true, listOf("myself") to true,
            listOf("hello") to false, listOf("hi") to false, listOf("dear") to false,
            listOf("speaking", "with") to false, listOf("speaking", "to") to false, listOf("talking", "to") to false,
        )
        val TITLES = setOf(
            "mr", "mrs", "ms", "miss", "shri", "smt", "dr", "doctor", "officer", "inspector", "constable",
            "agent", "sir", "madam", "sub", "senior", "junior", "head",
        )

        val ADDRESS_TRIGGERS = setOf(
            "address", "flat", "house", "plot", "sector", "street", "road", "nagar", "colony", "apartment",
            "apartments", "building", "floor", "lane", "village",
        )
        val DOB_TRIGGERS = listOf(listOf("date", "of", "birth"), listOf("born", "on"), listOf("dob"), listOf("birthday", "is"))

        /** Words that end a name: common English that follows "I am", "this is", "hello". */
        val STOP = setOf(
            "a", "an", "the", "and", "or", "but", "so", "to", "of", "in", "on", "at", "for", "with", "from", "by",
            "is", "am", "are", "was", "were", "be", "been", "being", "it", "its", "this", "that", "these", "those",
            "i", "me", "my", "you", "your", "he", "she", "we", "they", "them", "our", "their", "his", "her",
            "yes", "no", "not", "ok", "okay", "yeah", "sure", "fine", "good", "very", "really", "just", "also",
            "here", "there", "now", "then", "today", "tomorrow", "yesterday", "again", "please", "thank", "thanks",
            "sorry", "hello", "hi", "sir", "madam", "ji", "calling", "speaking", "talking", "going", "coming",
            "trying", "telling", "asking", "saying", "doing", "getting", "waiting", "listening", "worried",
            "scared", "afraid", "confused", "busy", "free", "ready", "done", "home", "office", "outside", "inside",
            "alone", "able", "unable", "afraid", "glad", "happy", "sad", "tired", "sick", "new", "old", "right",
            "wrong", "same", "different", "only", "still", "already", "almost", "about", "what", "who", "why",
            "how", "when", "where", "which", "can", "could", "will", "would", "shall", "should", "may", "might",
            "must", "do", "does", "did", "have", "has", "had", "get", "got", "go", "come", "tell", "say", "said",
            "know", "think", "want", "need", "see", "look", "call", "phone", "number", "account", "money",
            "everyone", "everybody", "anyone", "someone", "nobody", "nothing", "everything", "something",
            "reminder", "message", "update", "regarding", "about", "parcel", "delivery", "order", "sending",
            "verifying", "checking", "connected", "connecting", "online", "available", "interested", "aware",
            "customer", "valued", "dear", "all", "both", "each", "every", "any", "some", "many", "much", "more",
        )

        /** A small seed list of common Indian given names, for names said without an introduction. */
        val FIRST_NAMES = setOf(
            "ravi", "ravindra", "rahul", "rohan", "rohit", "amit", "anil", "sunil", "suresh", "ramesh", "mahesh",
            "rajesh", "rakesh", "mukesh", "dinesh", "ganesh", "vikram", "vijay", "ajay", "sanjay", "arjun",
            "karan", "kiran", "deepak", "manoj", "vinod", "ashok", "prakash", "arun", "varun", "tarun", "nikhil",
            "akhil", "sachin", "sandeep", "pradeep", "naveen", "praveen", "harish", "girish", "satish",
            "nitin", "sumit", "ankit", "ankur", "gaurav", "saurabh", "abhishek", "aditya", "akash", "vivek",
            "priya", "pooja", "neha", "anjali", "sneha", "kavya", "divya", "swati", "shreya", "anita", "sunita",
            "geeta", "seema", "rekha", "meena", "lakshmi", "radha", "sita", "asha", "usha", "nisha", "ritu",
            "kavita", "savita", "lata", "rani", "jyoti", "deepa", "shalini", "nandini", "aarti", "preeti",
            "sai", "krishna", "venkat", "srinivas", "lakshman", "murali", "gopal",
            "mohan", "sohan", "raju", "babu", "kumar", "priyanka", "aishwarya", "meera", "sana", "fatima", "ayesha",
            "imran", "salman", "arif", "farhan", "zaid", "joseph", "john", "thomas", "mary", "george",
        )
        val SURNAMES = setOf(
            "kumar", "sharma", "verma", "singh", "gupta", "patel", "reddy", "rao", "nair", "pillai", "iyer",
            "menon", "das", "khan", "ali", "joshi", "mehta", "shah", "jain", "agarwal", "mishra", "pandey",
            "yadav", "chauhan", "naidu", "shetty", "kapoor", "malhotra", "bose", "banerjee", "mukherjee",
        )
    }
}
