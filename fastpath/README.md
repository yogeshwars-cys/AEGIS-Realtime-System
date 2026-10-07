# AEGIS fast path

The on-phone real-time engine: **semantic observations in, events and an intervention step out**,
with no network anywhere on the way to the Reality Pause. The engine does not know what produced
the observations. Today a keyword lexicon over transcript text does; the trained semantic
extractor plugs into the same contract and nothing in the engine changes.

```
            any extractor (lexicon today, trained tagger next, audio model later)
                                    │  SegmentObservation  (the contract)
                                    ▼
core:  event folder ─► manipulation FSM ─► cumulative risk ─► evidence gate ─► friction ladder ─► REALITY PAUSE
                                    │  SemanticEvent (no text)
                                    ▼
uplink: egress auditor ─► journal (fsync) ─► transport            ◄── privacy: redacted text (transcript layer only)
```

## Run it

JDK 21. No Android SDK, phone or model needed.

```bash
./gradlew test              # 38 tests across all modules
./gradlew :replay:run       # replays scripts/ (text -> lexicon -> engine) and observations/ (straight into the engine)
./gradlew :replay:run --args="observations/external_tagger_digital_arrest.jsonl"
```

Per run, `build/replay/<name>/` holds `observations.jsonl` (exactly what the engine consumed) and
`egress.jsonl` (exactly what left the "phone").

## Plugging in the semantic extractor

The contract is `SegmentObservation` (`core/.../observation/SegmentObservation.kt`); its KDoc is the spec.
In short, per segment of conversation the extractor reports:

| Field | Meaning |
|---|---|
| `segment_id` | unique, increasing within a call; the extractor decides what a segment is |
| `final` | `false` for early revisable readings (optional), `true` exactly once per segment |
| `tactics` | the **complete** set seen in the segment so far, not a delta; a final that drops a tactic retracts it |
| `speaker` | `CALLER` / `VICTIM` / `UNKNOWN`; victim observations are accepted and ignored |
| `confidence` | calibrated 0..1 per tactic; the risk weights assume calibration |
| `source` | extractor name + version, e.g. `tagger-v2`; it travels in every event |

The label set is `Tactic` + `Qualifier` (`core/.../event/Tactic.kt`). Train against those names.

Three ways in, in the order you will probably use them:

1. **Prototype in anything (Python, on a laptop).** Emit one JSON line per observation in the
   `ObservationCodec` format and run `./gradlew :replay:run --args="your_file.jsonl"`. Add a
   `{"meta":{"expect_step":"PAUSE"}}` first line to make it a pass/fail check.
   `build/replay/*/observations.jsonl` from the lexicon is the baseline to beat, in the same format.
2. **On the phone, beside the lexicon.** Implement `SemanticExtractor<TranscriptUpdate>` and combine
   with `CompositeExtractor(listOf(LexiconExtractor(), YourTagger()))`. Merge happens before the
   engine (strongest confidence per tactic); a throwing model is counted and skipped.
3. **From audio directly.** Implement `SemanticExtractor<AudioChunk>` (or whatever the input is).
   The engine only ever sees `SegmentObservation`.

The acceptance test proves the engine is extractor-agnostic: replaying the recorded observations
with no text gives the same steps at the same moments as the live text run.

## Modules

| Module | What it owns |
|---|---|
| `core` | The engine and the contract. `SegmentObservation`, `SemanticExtractor`, `CompositeExtractor`, `ObservationCodec`, `SemanticEvent` (no text field), `EventFolder`, `ManipulationFsm`, `FastRisk`, `EvidenceGate`, `FrictionLadder`, `CallerPrior`, `FastPathEngine`. Pure JVM, no dependencies, no notion of text. |
| `transcript` | The text layer: `TranscriptUpdate`, `TextNormalizer`, `ScamLexicon` + `TokenAhoCorasick`, `LexiconExtractor` (the baseline extractor). |
| `privacy` | Redaction of transcript text before it may leave: `SpokenNumbers`, `PiiDetector`, `PrivacyFilter`, `EgressPayload`, `EgressAuditor`. Only relevant if text is sent; events never need it. |
| `uplink` | `EgressJournal` (write-ahead, checksummed, torn-tail repair), `Uplink` (audit -> dedupe -> journal -> send, in order). |
| `replay` | Script and observation-file runners, simulated ASR, CLI. |

## Rules enforced by structure, not convention

- **Only `EgressPayload` can leave.** The uplink takes nothing else. `RedactedSegment` has an
  `internal` constructor, so only `PrivacyFilter` can produce text that leaves the phone.
- **Testimony cannot pause a call.** Provisional ASR evidence and the caller prior move the
  ladder no further than NUDGE. The Reality Pause needs committed evidence of a *pattern*: an
  extraction tactic (remote access, credential, payment) plus a pressure or control tactic.
- **The ladder only climbs** within a call: no flapping warnings, no talking the risk back down.
- **Risk counts distinct tactics.** Repeating "OTP" ten times scores the same as once.
- **Only the caller's speech produces tactics.** The victim saying "OTP" is not a request.
- **Contract breaches are counted, not thrown.** Observations for another call or an already-final segment are dropped and show in `contractViolations`; the phone keeps protecting the user.
- **A failing extractor can never gate the others.** `CompositeExtractor` counts and skips it.

## What is real and what is simulated

| Real (this code ships to the phone) | Simulated / not built yet |
|---|---|
| Lexicon, event folding, FSM, risk, gate, ladder | **ASR.** `SimulatedAsr` spreads words at ~155 wpm, partial lag 300 ms, endpoint 600 ms. These are assumptions; the real figures come from sherpa-onnx on the device. |
| Privacy filter, auditor, salted hashing | **Trained extractor.** The contract and the JSONL path exist; only the lexicon implements it today. |
| Journal, idempotent uplink, crash recovery | **Android app**: audio capture, call screening, overlay, VoIP call source. |
| Engine processing time (measured: ~0.1 ms p50 per update on a laptop JVM) | **Network transport.** `JsonlFileTransport` stands in for the WebSocket. |

The six scripts in `scripts/` are synthetic. Replay results are evidence that the logic does what
it claims on those calls, not a detection-accuracy figure.

## Known limits

- English number words only; Hindi numerals in a Hinglish call are not normalised yet.
- Names are found after an introduction ("this is", "my name is", "hello") or from a small
  seed gazetteer. Unintroduced, unlisted names can slip through; the auditor's canary test
  is what measures that.
- Salted hashes of caller identifiers are pseudonymity, not privacy: a salt holder can confirm
  a guessed phone number.
- Lexicon confidences and tactic weights are hand-set priors, to be tuned on more scripts.
