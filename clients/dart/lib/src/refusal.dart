/// Why a client refused bytes it pulled.
///
/// `docs/reference/refusal-codes.md` opens with *"a code not listed here is not
/// a code"*, and it carries a **Client codes** table — five codes raised by a
/// device against bytes it pulled, never by the server. That table is the
/// protocol's vocabulary for this file, and [Refusal.specified] is which side
/// of it a reason sits on.
///
/// The distinction is load-bearing rather than tidy. A client surfaces a code
/// verbatim (`CONF-CLI-011`), so a library that spelled an internal reason like
/// a protocol code would be putting a word into that channel which the
/// specification says does not exist. [vocabularyCode] is therefore null for
/// every library-local reason, and `refusal_vocabulary_test.dart` reads the
/// table out of the document to check the five that are not.
library;

/// A reason a client refused.
enum Refusal {
  // ── The five in the document's Client codes table ──────────────────────

  /// The envelope's signature does not verify.
  ///
  /// Terminal and without remedy: these bytes are forged. Never merged with
  /// [unknownAuthorKey] — the document lists that pair under *codes that must
  /// never be merged*, because *I hold no key to check these against here* has
  /// a second cause and an entirely different investigation.
  badSignature(code: 'bad_signature', specified: true),

  /// The `author_key_id` resolves to no key in force for that device at that
  /// op's own position. `CONF-CLI-026`.
  unknownAuthorKey(code: 'unknown_author_key', specified: true),

  /// The body did not open under the epoch key.
  ///
  /// Distinct from [badSignature] by construction: the signature is taken over
  /// the *sealed* bytes, so tampered ciphertext fails the signature first. A
  /// body that will not open despite a valid signature means something else —
  /// bytes the author really signed that still will not decrypt.
  aeadFailure(code: 'aead_failure', specified: true),

  /// Unsealed content at a log position after the Workspace's first `rotate`,
  /// or at any position where epoch 0 is keyed. `CONF-CLI-006`.
  plaintextAtEncryptedEpoch(
    code: 'plaintext_at_encrypted_epoch',
    specified: true,
  ),

  /// A load-bearing control type this reader does not serve. `CONF-CLI-024`.
  controlTypeNotServed(code: 'control_type_not_served', specified: true),

  // ── Library-local reasons, which are not protocol codes ────────────────

  /// Fewer bytes than the suite's geometry admits, or a body that is not a
  /// legal size class.
  malformedEnvelope(),

  /// A suite byte this client does not serve. `CONF-CLI-028`.
  ///
  /// Not `unsupported_suite`: that is a **server** code, raised at `POST
  /// …/ops` against an op somebody tried to write. A reader that met such an
  /// envelope is in the opposite position — it pulled bytes another server
  /// already accepted — and the remedy is to keep them, not to report them.
  suiteNotServed(),

  /// A header field with exactly one legal value carried another.
  ///
  /// Two requirements land here. `CONF-CLI-023`: at suite `0x00` the `nonce`
  /// and `key_epoch` have one legal value each. `CONF-CLI-003`: in v1
  /// `observed_head` has one, at every suite. The server judges none of the
  /// three, so a non-zero one arrives at a client unchallenged — which makes
  /// this the client's to refuse or nobody's.
  illegalFieldValue(),

  /// A member wrap that is not 104 bytes, or an escrow wrap that is not 72.
  ///
  /// Kept apart from [aeadFailure] deliberately: a wrap of the wrong length
  /// never reached the AEAD, so reporting it as a failure to authenticate would
  /// claim a cryptographic verdict that was never computed.
  malformedWrap(),

  /// The client holds no public key at all for this `author_key_id`.
  ///
  /// Separate from [unknownAuthorKey], which is positional: that one says *I
  /// know this device and this is not its key here*. This one says *I have
  /// never heard of this key*, which is what an untrusted author looks like to
  /// a reader with no log to place it in.
  untrustedKey(),

  /// `prev_author_hash` does not match the client's own verified head for this
  /// author. `CONF-CLI-002`.
  brokenAuthorChain(),

  /// A control op's `prev_control_hash` does not match the previous control
  /// payload's hash, or a non-genesis carried a zero one. `CONF-CLI-007`.
  brokenControlChain(),

  /// The published wrap set does not hash to the digest the signed `rotate`
  /// committed to.
  ///
  /// Deterministic, and `docs/04-keys.md` is explicit that a well-behaved
  /// client terminalises it — which is also why a client must not compute it
  /// from a sort order of its own invention.
  keywrapDigestMismatch();

  /// Library-local reasons pass no `code`: they have no wire spelling, because
  /// the document gives them none.
  const Refusal({String? code, this.specified = false})
      : _code = code,
        assert(
          !specified || code != null,
          'a specified code must carry its spelling from the document',
        );

  final String? _code;

  /// Whether this reason is one of the five in the document's Client codes
  /// table. A `false` here means the reason is this library's, and must never
  /// be surfaced as though the protocol had named it.
  final bool specified;

  /// The wire spelling, for the five the document names — null otherwise.
  String? get vocabularyCode => specified ? _code : null;

  /// A stable name for logs and test failures. For a specified code this is
  /// the document's spelling; otherwise it is the enum's own name, which
  /// cannot be mistaken for a protocol code.
  String get label => _code ?? name;

  @override
  String toString() => label;
}

/// Thrown when a client refuses. Carries the reason unchanged so a caller can
/// distinguish *I do not know this key* from *this is a forgery* — a
/// distinction the specification requires be kept (`CONF-CLI-011`).
class RefusedException implements Exception {
  const RefusedException(this.refusal, [this.detail]);

  final Refusal refusal;
  final String? detail;

  @override
  String toString() => 'RefusedException(${refusal.label}'
      '${detail == null ? '' : ': $detail'})';
}
