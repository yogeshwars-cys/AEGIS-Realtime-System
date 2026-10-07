package org.aegis.fastpath.transcript

import org.aegis.fastpath.event.Qualifier
import org.aegis.fastpath.event.Tactic

/**
 * Tier 1 of semantic extraction: deterministic, sub-millisecond, safe to run on every ASR
 * partial.
 *
 * Two passes. A [TokenAhoCorasick] finds *atoms* (an organisation, a request verb, a
 * credential noun, a remote-access app) in one scan. Composite rules then turn atoms into
 * tactics: a credential noun on its own is a mention, a request verb near it is a request.
 *
 * The rule that matters most for false positives is negation. Real banks say "SBI will never
 * ask for your OTP" and "do not install AnyDesk", which carry exactly the words a scammer
 * uses. A negatable rule is suppressed when a negation word sits in the five tokens before
 * it. Negation words that are part of a matched phrase ("don't disconnect") are not
 * negations of anything else, and "don't worry" / "don't be scared" / "no problem" never count.
 *
 * Every confidence here is a prior to be tuned on the replay scripts, not a measurement.
 */
class ScamLexicon {

    enum class Atom {
        ORG, SELF_INTRO,
        TIME_PRESSURE, WITHIN, TIME_UNIT, THREAT_WORD,
        REMOTE_APP, INSTALL, PHISH_LINK,
        CREDENTIAL, REQUEST,
        PAY_VERB, PAY_TARGET, PAY_STRONG,
        REWARD,
        ISOLATION_PHRASE, SECRECY_PHRASE, BYPASS_PHRASE,
        /** Shadows shorter atoms it contains: "pin code" is an address, not a PIN. */
        NEUTRAL,
    }

    data class AtomDef(val atom: Atom, val qualifier: Qualifier = Qualifier.NONE, val strong: Boolean = false)

    data class AtomHit(val def: AtomDef, val start: Int, val end: Int) {
        val atom: Atom get() = def.atom
    }

    private val automaton: TokenAhoCorasick<AtomDef>

    /** Every token any lexicon phrase uses. The privacy filter reads this to avoid mistaking "sbi" for a name. */
    val vocabulary: Set<String>

    init {
        val phrases = HashMap<List<String>, AtomDef>()
        fun add(atom: Atom, vararg forms: String, qualifier: Qualifier = Qualifier.NONE, strong: Boolean = false) {
            for (form in forms) {
                val toks = TextNormalizer.tokens(form)
                require(toks.isNotEmpty()) { "blank lexicon entry" }
                check(phrases.put(toks, AtomDef(atom, qualifier, strong)) == null) { "duplicate lexicon entry: $form" }
            }
        }

        add(Atom.ORG, "sbi", "state bank", "state bank of india", "hdfc", "hdfc bank", "icici", "icici bank",
            "axis bank", "kotak", "pnb", "punjab national bank", "bank of baroda", "canara bank", "union bank",
            "rbi", "reserve bank", "bank", "paytm", "phonepe", qualifier = Qualifier.BANK)
        add(Atom.ORG, "police", "cbi", "crime branch", "cyber crime", "cyber cell", "customs", "narcotics",
            "ncb", "enforcement directorate", "interpol", "court", qualifier = Qualifier.POLICE, strong = true)
        add(Atom.ORG, "trai", "income tax", "income tax department", "uidai", "aadhaar department",
            "telecom department", "department of telecommunications", "government", "ministry",
            "electricity board", "electricity department", qualifier = Qualifier.GOVT, strong = true)
        add(Atom.ORG, "jio", "airtel", "vodafone", "bsnl", "sim card", qualifier = Qualifier.TELECOM)
        add(Atom.ORG, "fedex", "dhl", "blue dart", "bluedart", "courier", "delhivery", "india post",
            qualifier = Qualifier.COURIER)

        add(Atom.SELF_INTRO, "calling from", "i am calling", "im calling", "i am from", "im from", "this is",
            "speaking from", "on behalf of", "from the", "officer", "inspector", "manager", "executive",
            "department", "head office", "customer care", "helpline", "desk", "official", "support team")

        add(Atom.TIME_PRESSURE, "immediately", "right now", "urgent", "urgently", "asap", "today itself",
            "last chance", "final warning", "final notice", "deadline", "right away", "hurry", "quickly",
            "at the earliest", "as soon as possible", "before it is too late", "no time")
        add(Atom.WITHIN, "within", "in next", "in the next", "only")
        add(Atom.TIME_UNIT, "minutes", "minute", "mins", "hours", "hour", "seconds")
        add(Atom.THREAT_WORD, "blocked", "block", "frozen", "freeze", "suspended", "suspend", "deactivated",
            "deactivate", "closed permanently", "arrest", "arrested", "arrest warrant", "warrant", "legal action",
            "fir", "police case", "case registered", "case against you", "jail", "digital arrest", "penalty",
            "seized", "illegal", "money laundering", "drugs", "summons", "non bailable", "lose all your money")

        add(Atom.REMOTE_APP, "anydesk", "any desk", "teamviewer", "team viewer", "quicksupport", "quick support",
            "rustdesk", "rust desk", "airdroid", "ultraviewer", "screen share", "screen sharing",
            "share your screen", "share screen", "remote access", "remote app", "support app")
        add(Atom.INSTALL, "install", "download", "open play store", "play store", "app store", "open the app")
        add(Atom.PHISH_LINK, "click the link", "click on the link", "link i sent", "link i have sent",
            "open the link", "apk", "apk file")

        add(Atom.CREDENTIAL, "otp", "one time password", "pin", "upi pin", "mpin", "atm pin", "cvv", "password",
            "net banking password", "card number", "expiry date", "expiry", "verification code", "security code",
            "code you received", "code sent",
            // Identity data asked for "verification": the same extraction step as an OTP.
            "aadhaar", "aadhaar number", "aadhar", "pan number", "pan card", "account number", "card details",
            "bank details", "date of birth")
        add(Atom.REQUEST, "share", "tell", "tell me", "read", "read out", "give", "send", "enter", "type",
            "provide", "confirm", "ask for", "asks for", "asking for", "need", "say", "forward", "spell",
            "verify", "what is your", "what is the")

        add(Atom.PAY_VERB, "transfer", "pay", "deposit", "send money", "send the money", "move your money",
            "move the money", "scan", "approve", "accept the request", "collect request")
        add(Atom.PAY_TARGET, "account", "upi id", "qr code", "qr", "money", "amount", "rupees", "savings",
            "funds", "fee", "balance", "fixed deposit", "fd")
        add(Atom.PAY_STRONG, "safe account", "secure account", "verification account", "rbi account",
            "government account", "escrow account", "refundable", "verification amount", "processing fee",
            "registration fee", "clearance fee", "security deposit")

        add(Atom.REWARD, "lottery", "prize", "you have won", "you won", "cashback", "lucky draw", "kbc",
            "kaun banega crorepati", "reward points", "bonus", "gift", "refund", "jackpot", "selected for",
            "double your money", "guaranteed returns", "investment returns")

        add(Atom.ISOLATION_PHRASE, "dont disconnect", "do not disconnect", "not disconnect", "dont cut the call",
            "do not cut the call", "dont cut", "dont hang up", "do not hang up", "stay on the line", "stay on call",
            "stay on the call", "keep the call on", "keep the line open", "dont put the phone down", "go to a room",
            "go to a separate room", "be alone", "close the door", "lock the door", "switch off your phone",
            "dont take other calls", "do not take any other call", "keep your camera on")
        add(Atom.SECRECY_PHRASE, "dont tell anyone", "do not tell anyone", "dont tell your family",
            "do not tell your family", "dont inform anyone", "do not inform anyone", "dont inform",
            "keep this confidential", "this is confidential", "strictly confidential", "keep it secret",
            "keep this secret", "dont share this with", "do not share this with", "dont discuss", "do not discuss",
            "nobody should know", "no one should know")
        add(Atom.BYPASS_PHRASE, "dont go to the branch", "do not go to the branch", "no need to visit",
            "no need to go", "dont call the bank", "do not call the bank", "dont call customer care",
            "do not contact the bank", "dont contact the bank", "dont visit the branch", "i am the bank",
            "this is the official number", "you can trust me", "we have already verified", "no need to verify",
            "dont verify", "you dont need to check", "dont check with anyone")

        add(Atom.NEUTRAL, "pin code", "pincode", "zip code", "dress code")

        automaton = TokenAhoCorasick(phrases)
        vocabulary = phrases.keys.flatten().toSet()
    }

    fun atoms(tokens: List<String>): List<AtomHit> {
        val raw = automaton.scan(tokens).map { AtomHit(it.value, it.start, it.endExclusive) }
        val neutral = raw.filter { it.atom == Atom.NEUTRAL }
        return raw.filter { a ->
            a.atom != Atom.NEUTRAL && neutral.none { n -> a.start >= n.start && a.end <= n.end }
        }
    }

    fun scan(text: String): List<TacticHit> = scanTokens(TextNormalizer.tokens(text))

    fun scanTokens(tokens: List<String>): List<TacticHit> {
        val atoms = atoms(tokens)

        // Negation words inside a matched phrase belong to that phrase.
        val inPhrase = BooleanArray(tokens.size)
        for (a in atoms) for (i in a.start until a.end) if (tokens[i] in NEGATIONS) inPhrase[i] = true
        // "don't worry", "don't be scared", "no problem" reassure; they negate nothing.
        fun reassurance(i: Int): Boolean {
            val next = tokens.getOrNull(i + 1)
            return next in REASSURANCE || (next == "be" && tokens.getOrNull(i + 2) in REASSURANCE)
        }
        val negationAt = BooleanArray(tokens.size) { i ->
            tokens[i] in NEGATIONS && !inPhrase[i] && !reassurance(i)
        }
        fun negated(start: Int): Boolean = (maxOf(0, start - NEGATION_WINDOW) until start).any { negationAt[it] }

        val by = atoms.groupBy { it.atom }
        fun of(atom: Atom): List<AtomHit> = by[atom].orEmpty()
        fun near(a: AtomHit, b: AtomHit, window: Int): Boolean = maxOf(a.start, b.start) - minOf(a.end, b.end) <= window

        val hits = mutableListOf<TacticHit>()
        fun hit(tactic: Tactic, conf: Double, start: Int, end: Int, q: Qualifier = Qualifier.NONE) {
            hits.add(TacticHit(tactic, q, conf, start, end))
        }

        // Phrases that carry their own negation: never negatable.
        for (a in of(Atom.ISOLATION_PHRASE)) hit(Tactic.ISOLATION, 0.90, a.start, a.end)
        for (a in of(Atom.SECRECY_PHRASE)) hit(Tactic.SECRECY, 0.90, a.start, a.end)
        for (a in of(Atom.BYPASS_PHRASE)) hit(Tactic.VERIFICATION_BYPASS, 0.85, a.start, a.end)

        // Authority: an organisation plus the caller presenting themselves as part of it.
        for (org in of(Atom.ORG)) {
            val intro = of(Atom.SELF_INTRO).any { near(it, org, AUTHORITY_WINDOW) }
            when {
                intro -> hit(Tactic.AUTHORITY_CLAIM, 0.85, org.start, org.end, org.def.qualifier)
                org.def.strong -> hit(Tactic.AUTHORITY_CLAIM, 0.60, org.start, org.end, org.def.qualifier)
            }
        }

        for (a in of(Atom.TIME_PRESSURE)) if (!negated(a.start)) hit(Tactic.URGENCY, 0.70, a.start, a.end)
        for (w in of(Atom.WITHIN)) {
            val unit = of(Atom.TIME_UNIT).firstOrNull { it.start > w.start && it.start - w.end <= 3 }
            if (unit != null && !negated(w.start)) hit(Tactic.URGENCY, 0.85, w.start, unit.end)
        }
        for (a in of(Atom.THREAT_WORD)) if (!negated(a.start)) hit(Tactic.THREAT, 0.80, a.start, a.end)

        for (app in of(Atom.REMOTE_APP)) {
            val install = of(Atom.INSTALL).firstOrNull { near(it, app, 6) }
            val start = minOf(app.start, install?.start ?: app.start)
            if (negated(start)) continue
            val end = maxOf(app.end, install?.end ?: app.end)
            hit(Tactic.REMOTE_ACCESS_REQUEST, if (install != null) 0.95 else 0.75, start, end)
        }
        for (a in of(Atom.PHISH_LINK)) if (!negated(a.start)) hit(Tactic.REMOTE_ACCESS_REQUEST, 0.60, a.start, a.end)

        for (cred in of(Atom.CREDENTIAL)) {
            val req = of(Atom.REQUEST).firstOrNull { near(it, cred, 6) } ?: continue
            val start = minOf(req.start, cred.start)
            if (!negated(start)) hit(Tactic.CREDENTIAL_REQUEST, 0.90, start, maxOf(req.end, cred.end))
        }

        for (a in of(Atom.PAY_STRONG)) if (!negated(a.start)) hit(Tactic.PAYMENT_REQUEST, 0.85, a.start, a.end)
        for (verb in of(Atom.PAY_VERB)) {
            val target = of(Atom.PAY_TARGET).firstOrNull { near(it, verb, 6) } ?: continue
            val start = minOf(verb.start, target.start)
            if (!negated(start)) hit(Tactic.PAYMENT_REQUEST, 0.80, start, maxOf(verb.end, target.end))
        }

        for (a in of(Atom.REWARD)) if (!negated(a.start)) hit(Tactic.REWARD_LURE, 0.70, a.start, a.end)

        // One hit per (tactic, qualifier): the strongest, earliest on ties.
        return hits.groupBy { it.tactic to it.qualifier }
            .map { (_, group) -> group.sortedWith(compareBy({ -it.confidence }, { it.tokenStart })).first() }
            .sortedBy { it.tokenStart }
    }

    companion object {
        const val NEGATION_WINDOW = 5
        const val AUTHORITY_WINDOW = 8
        val NEGATIONS = setOf("not", "never", "dont", "no", "didnt", "doesnt", "wont", "cannot", "cant", "nobody")
        val REASSURANCE = setOf(
            "worry", "worried", "panic", "tension", "fear", "scared", "afraid", "problem", "issue",
        )
    }
}
