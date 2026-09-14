/// Certificates, the device login, and the vault record.
///
/// The signatures here are separate from the envelope's, and they say something
/// different. An envelope signature says *this device sent this*. A certificate
/// signature says *this authority approved this fact*. They come apart because
/// the approver is usually not the sender: Root signs a registration, and the
/// device being registered is what posts it.
///
/// Written from `docs/03-authority.md` and `docs/04-keys.md`, and checked
/// against `vectors/auth.json`.
library;

import 'dart:typed_data';

import 'crypto.dart' as crypto;
import 'refusal.dart';
import 'wire.dart';

/// The nine documents a control op can carry, as they are spelled in a domain.
///
/// A closed set, because the domain table is closed. The spelling matters: the
/// domain is what stops one document's signature verifying as another's, so a
/// typo here would not be a cosmetic bug — it would be a verifier that accepts
/// a grant presented as a revoke.
enum CertificateDocument {
  workspaceGenesis('workspace-genesis'),
  memberRegister('member-register'),
  memberAmend('member-amend'),
  grant('grant'),
  revoke('revoke'),
  roleTable('role-table'),
  delegate('delegate'),
  revokeDelegation('revoke-delegation'),
  rootHandover('root-handover');

  const CertificateDocument(this.document);

  /// The `<document>` in `framed(<ns>/<document>/v1, …)`.
  final String document;

  String domain(String namespace) => '$namespace/$document/v1';
}

/// The Root in force over a span of the log.
///
/// A Root is not a constant. `root_handover` replaces it, and a log that spans
/// one must still replay: every certificate is verified against the Root in
/// force **at that certificate's own position**, not the current one
/// (`CONF-HAND-005`). A verifier that used the current Root would refuse every
/// certificate written before the handover — a correct history, rejected.
class RootEpoch {
  RootEpoch({required this.fromSeq, required List<int> rootPublicKey})
      : rootPublicKey = Uint8List.fromList(rootPublicKey) {
    if (rootPublicKey.length != 32) {
      throw ArgumentError('a Root public key is 32 bytes');
    }
  }

  /// The first position at which this Root is in force, inclusive.
  final int fromSeq;

  final Uint8List rootPublicKey;
}

/// Root authority over the life of a Workspace.
class RootTimeline {
  RootTimeline(List<RootEpoch> epochs)
      : _epochs = List<RootEpoch>.of(epochs)
          ..sort((a, b) => a.fromSeq.compareTo(b.fromSeq)) {
    if (_epochs.isEmpty) {
      throw ArgumentError('a Workspace has at least a founding Root');
    }
  }

  final List<RootEpoch> _epochs;

  /// The Root in force at [seq], or null below the founding Root's position.
  Uint8List? rootAt(int seq) {
    Uint8List? found;
    for (final e in _epochs) {
      if (e.fromSeq <= seq) {
        found = e.rootPublicKey;
      }
    }
    return found;
  }

  /// The current Root — the one a fresh device adopts, and the wrong answer for
  /// any certificate below the last handover.
  Uint8List get current => _epochs.last.rootPublicKey;
}

/// Verify a certificate's signature over its **literal** bytes.
///
/// `docs/03-authority.md` is emphatic: *signed bytes, never re-serialised
/// JSON*. A verifier that parses a certificate and re-encodes what it parsed is
/// verifying a document nobody signed — and will accept or reject on key order,
/// whitespace and number formatting, none of which the signer committed to.
/// Hence [certBytes] is bytes, and this function is given no way to reach a
/// parsed form.
///
/// Returns false rather than throwing on every failure mode, for the reason
/// `crypto.verify` gives: a caller refuses on all of them identically.
Future<bool> verifyCertificate({
  required String namespace,
  required CertificateDocument document,
  required List<int> certBytes,
  required List<int> authorityPublicKey,
  required List<int> signature,
}) =>
    crypto.verify(
      authorityPublicKey,
      certInput(namespace, document.document, certBytes),
      signature,
    );

/// Verify a certificate against the Root in force at its own position.
///
/// `CONF-HAND-005`. Throws [Refusal.badSignature] on a forgery, and
/// [Refusal.untrustedKey] below the founding Root — where the client holds no
/// Root for that position at all, which is a different situation from a bad
/// signature and must not be reported as one.
Future<void> verifyCertificateAtPosition({
  required String namespace,
  required CertificateDocument document,
  required List<int> certBytes,
  required List<int> signature,
  required RootTimeline roots,
  required int atSeq,
}) async {
  final root = roots.rootAt(atSeq);
  if (root == null) {
    throw RefusedException(
      Refusal.untrustedKey,
      'no Root in force at seq $atSeq',
    );
  }
  final ok = await verifyCertificate(
    namespace: namespace,
    document: document,
    certBytes: certBytes,
    authorityPublicKey: root,
    signature: signature,
  );
  if (!ok) {
    throw RefusedException(
      Refusal.badSignature,
      '${document.document} certificate at seq $atSeq does not verify under '
      'the Root in force there',
    );
  }
}

/// Verify a device's answer to an auth challenge.
///
/// `framed(<ns>/auth-challenge/v1, member_id ‖ nonce)`, where `member_id` is
/// the **16 raw bytes** of the id and never a textual spelling — the same rule
/// as the derived-id name and the digest sort key, for the same reason. A
/// textual identifier has spellings; raw bytes do not, so the hazard does not
/// exist rather than being mitigated.
Future<bool> verifyAuthChallenge({
  required String namespace,
  required List<int> memberId,
  required List<int> nonce,
  required List<int> controlPublicKey,
  required List<int> signature,
}) {
  if (memberId.length != 16) {
    throw ArgumentError('member_id is the 16 raw bytes of the id');
  }
  return crypto.verify(
    controlPublicKey,
    authChallengeInput(namespace, memberId, nonce),
    signature,
  );
}

/// A vault record, as the server stores it and serves it back.
class VaultRecord {
  VaultRecord({
    required List<int> locator,
    required this.version,
    required List<int> blob,
    required List<int> rootPublicKey,
    required List<int> rootSignature,
  })  : locator = Uint8List.fromList(locator),
        blob = Uint8List.fromList(blob),
        rootPublicKey = Uint8List.fromList(rootPublicKey),
        rootSignature = Uint8List.fromList(rootSignature) {
    if (locator.length != 32) {
      throw ArgumentError('a locator is 32 bytes');
    }
  }

  /// 32 bytes, derived on the device from the wrapping secret.
  ///
  /// The **only** value derived from that secret which may leave the device
  /// (`CONF-CLI-010`).
  final Uint8List locator;

  final int version;

  /// Opaque to the server, which stores it verbatim and must not even
  /// length-check it.
  final Uint8List blob;

  /// The Root this record **installs** — not necessarily the one that signed
  /// it. The two differ on exactly one kind of write: the one that follows a
  /// `root_handover`.
  final Uint8List rootPublicKey;

  final Uint8List rootSignature;
}

/// The bytes a vault record is signed over.
///
/// `framed(<ns>/vault/v1, locator ‖ version u64 ‖ blob)`. The locator is inside
/// the signed bytes, so a record signed for one slot can never be replayed into
/// another.
Uint8List vaultSigningInput(String namespace, VaultRecord record) =>
    vaultInput(namespace, record.locator, record.version, record.blob);

/// Verify a vault record under the key that was entitled to sign it.
///
/// [signingRoot] is **the slot's currently pinned Root** — and on a first write,
/// the `root_pk` the record itself declares. It is not always
/// `record.rootPublicKey`: after a `root_handover`, the outgoing Root signs the
/// record that installs the incoming one. Only the outgoing key can attest that
/// a succession is intended; a signature by the incoming key would prove
/// nothing, because anyone can mint a keypair.
Future<bool> verifyVaultRecord({
  required String namespace,
  required VaultRecord record,
  required List<int> signingRoot,
}) =>
    crypto.verify(
      signingRoot,
      vaultSigningInput(namespace, record),
      record.rootSignature,
    );

/// Check the `root_pk` served beside a vault record against the Root actually
/// recovered from the blob.
///
/// `CONF-CLI-008`. A mismatch is a **corrupt record, not a key to adopt** —
/// which is the entire point. The served `root_pk` is a claim by the party that
/// stored it; the key recovered from the blob is the one the client derived
/// under its own secret. Believing the former over the latter would let whoever
/// holds the slot re-pin it.
void checkVaultRootMatchesRecovered({
  required VaultRecord record,
  required List<int> recoveredRootPublicKey,
}) {
  if (_hex(record.rootPublicKey) != _hex(recoveredRootPublicKey)) {
    throw RefusedException(
      Refusal.untrustedKey,
      'the served root_pk is not the Root recovered from the blob: this is a '
      'corrupt record, and the served key is not a key to adopt',
    );
  }
}

/// What a founding client must do in order, and a guard that it did.
///
/// `CONF-CLI-015`: a founding client lands its `workspace_genesis` **before**
/// writing the vault slot that recovers it. The other order leaves a slot that
/// recovers a Workspace which does not exist — and if the genesis then fails,
/// a recovery route to nothing.
class FoundingCeremony {
  bool _genesisLanded = false;

  bool get genesisLanded => _genesisLanded;

  void genesisDidLand() => _genesisLanded = true;

  /// Throws unless the genesis has landed.
  void requireGenesisBeforeVaultWrite() {
    if (!_genesisLanded) {
      throw StateError(
        'workspace_genesis must land before the vault slot that recovers it',
      );
    }
  }
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
