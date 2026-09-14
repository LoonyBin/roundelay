/// The key plane: how an epoch key reaches the devices that may read, and how
/// a body is sealed under it.
///
/// This is the layer that makes the server's content-blindness cryptographic
/// rather than a policy it promises to keep. Everything here runs on the
/// device; the server holds wraps it cannot open and a digest it cannot forge.
///
/// Written from `docs/04-keys.md`, and checked against `vectors/keyplane.json`.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'crypto.dart' as crypto;
import 'refusal.dart';
import 'wire.dart';

/// `epk 32 ‖ nonce 24 ‖ XChaCha20-Poly1305(K 32) + tag 16`.
const int memberWrapLen = 104;

/// `nonce 24 ‖ XChaCha20-Poly1305(K 32) + tag 16`.
const int escrowWrapLen = 72;

const int epochKeyLen = 32;
const int wrapNonceLen = 24;
const int x25519KeyLen = 32;
const int memberIdLen = 16;
const int kexKeyIdLen = 8;

/// RFC 5869's default salt: **32 zero bytes, not a zero-length key**.
///
/// `docs/04-keys.md` states this as a fork point rather than a detail, and it
/// is worth repeating where the value lives. HMAC pads a short key with zeros,
/// so 32 zero bytes and an empty salt happen to agree — but a library that
/// rejects an empty salt, or substitutes a default of its own, produces a
/// different key, and nothing in the ciphertext says which happened.
Uint8List get hkdfSalt => Uint8List(32);

final _aead = Xchacha20.poly1305Aead();

/// `info = framed(<ns>/keywrap/v1, epk ‖ workspace_id ‖ epoch ‖ member_id
/// ‖ kex_key_id)`.
///
/// Both the HKDF info and the AEAD associated data, which is why a mismatch on
/// any field in it is an authentication failure rather than a silent decryption
/// to garbage. Every field pins the wrap to one slot: the `epk` so it cannot be
/// re-pointed at another ephemeral share, the Workspace and epoch so it cannot
/// be replayed elsewhere, and the member and key id so it cannot be handed to
/// another device — or to another sealing key of the same device.
Uint8List memberWrapInfo({
  required String namespace,
  required List<int> ephemeralPublicKey,
  required List<int> workspaceId,
  required int epoch,
  required List<int> memberId,
  required List<int> kexKeyId,
}) {
  _expect(ephemeralPublicKey, x25519KeyLen, 'epk');
  _expect(workspaceId, 16, 'workspace_id');
  _expect(memberId, memberIdLen, 'member_id');
  _expect(kexKeyId, kexKeyIdLen, 'kex_key_id');
  return crypto.framed('$namespace/keywrap/v1', [
    ephemeralPublicKey,
    workspaceId,
    _u32(epoch),
    memberId,
    kexKeyId,
  ]);
}

/// `info = framed(<ns>/epoch-key-escrow/v1, workspace_id ‖ epoch)`.
Uint8List escrowWrapInfo({
  required String namespace,
  required List<int> workspaceId,
  required int epoch,
}) {
  _expect(workspaceId, 16, 'workspace_id');
  return crypto.framed('$namespace/epoch-key-escrow/v1', [
    workspaceId,
    _u32(epoch),
  ]);
}

/// One device's copy of an epoch key, as it is published and as the digest
/// names it.
class MemberWrap {
  MemberWrap({
    required List<int> memberId,
    required List<int> kexKeyId,
    required List<int> wrap,
  })  : memberId = _copy(memberId, memberIdLen, 'member_id'),
        kexKeyId = _copy(kexKeyId, kexKeyIdLen, 'kex_key_id'),
        wrap = Uint8List.fromList(wrap);

  /// The 16 **raw** bytes of the member id, never a textual spelling.
  final Uint8List memberId;

  /// The 8-byte derived id of the device sealing key this wrap is under.
  final Uint8List kexKeyId;

  final Uint8List wrap;

  /// The ephemeral public key the wrap carries in its own first 32 bytes.
  Uint8List get ephemeralPublicKey =>
      Uint8List.sublistView(wrap, 0, x25519KeyLen);

  Uint8List get nonce => Uint8List.sublistView(wrap, 32, 32 + wrapNonceLen);

  Uint8List get sealedKey => Uint8List.sublistView(wrap, 32 + wrapNonceLen);
}

/// Derive the wrap key from an already-agreed X25519 shared secret.
///
/// Exposed because the two sides reach the same secret from opposite ends —
/// the minter from its ephemeral private key and the device's published
/// sealing key, the device from its own sealing private key and the `epk`
/// inside the wrap. A test holding either half can therefore drive the real
/// construction, which is what lets `vectors/keyplane.json` be checked by its
/// actual ciphertext rather than only by its `info`.
Future<SecretKey> deriveWrapKey(List<int> sharedSecret, List<int> info) =>
    Hkdf(hmac: Hmac.sha256(), outputLength: epochKeyLen).deriveKey(
      secretKey: SecretKey(sharedSecret),
      nonce: hkdfSalt,
      info: info,
    );

/// X25519 over a 32-byte private scalar and a 32-byte public key.
Future<Uint8List> x25519(List<int> privateKey, List<int> publicKey) async {
  _expect(privateKey, x25519KeyLen, 'x25519 private key');
  _expect(publicKey, x25519KeyLen, 'x25519 public key');
  final keyPair = await X25519().newKeyPairFromSeed(privateKey);
  final shared = await X25519().sharedSecretKey(
    keyPair: keyPair,
    remotePublicKey: SimplePublicKey(publicKey, type: KeyPairType.x25519),
  );
  return Uint8List.fromList(await shared.extractBytes());
}

/// The X25519 public key for a 32-byte private scalar.
Future<Uint8List> x25519Public(List<int> privateKey) async {
  _expect(privateKey, x25519KeyLen, 'x25519 private key');
  final keyPair = await X25519().newKeyPairFromSeed(privateKey);
  final pk = await keyPair.extractPublicKey();
  return Uint8List.fromList(pk.bytes);
}

/// Mint one device's wrap of [contentKey].
///
/// [ephemeralPrivateKey] and [nonce] are parameters rather than sampled here so
/// the frozen vectors can be reproduced byte for byte. A real minting samples
/// both fresh per wrap, and reusing either across two wraps of different keys
/// under the same recipient destroys the construction.
Future<MemberWrap> mintMemberWrap({
  required String namespace,
  required List<int> workspaceId,
  required int epoch,
  required List<int> contentKey,
  required List<int> memberId,
  required List<int> kexPublicKey,
  required List<int> ephemeralPrivateKey,
  required List<int> nonce,
}) async {
  _expect(contentKey, epochKeyLen, 'epoch key');
  _expect(nonce, wrapNonceLen, 'wrap nonce');
  final epk = await x25519Public(ephemeralPrivateKey);
  final kexKeyId = crypto.keyId(kexPublicKey);
  final info = memberWrapInfo(
    namespace: namespace,
    ephemeralPublicKey: epk,
    workspaceId: workspaceId,
    epoch: epoch,
    memberId: memberId,
    kexKeyId: kexKeyId,
  );
  final shared = await x25519(ephemeralPrivateKey, kexPublicKey);
  final box = await _aead.encrypt(
    contentKey,
    secretKey: await deriveWrapKey(shared, info),
    nonce: nonce,
    aad: info,
  );
  return MemberWrap(
    memberId: memberId,
    kexKeyId: kexKeyId,
    wrap: <int>[...epk, ...nonce, ...box.cipherText, ...box.mac.bytes],
  );
}

/// Open a wrap addressed to this device, returning the epoch key.
///
/// The `epk` is read from the wrap, but every other field of `info` comes from
/// what the caller already believes — its own member id, the Workspace, the
/// epoch, its own sealing key. So a wrap moved to another slot does not open:
/// the caller reconstructs the `info` of the slot it thinks it is filling, and
/// that is the associated data.
Future<Uint8List> openMemberWrap({
  required String namespace,
  required MemberWrap wrap,
  required List<int> workspaceId,
  required int epoch,
  required List<int> memberId,
  required List<int> kexPrivateKey,
}) async {
  if (wrap.wrap.length != memberWrapLen) {
    throw RefusedException(
      Refusal.malformedWrap,
      'a member wrap is $memberWrapLen bytes, got ${wrap.wrap.length}',
    );
  }
  final kexPublicKey = await x25519Public(kexPrivateKey);
  final info = memberWrapInfo(
    namespace: namespace,
    ephemeralPublicKey: wrap.ephemeralPublicKey,
    workspaceId: workspaceId,
    epoch: epoch,
    memberId: memberId,
    kexKeyId: crypto.keyId(kexPublicKey),
  );
  final shared = await x25519(kexPrivateKey, wrap.ephemeralPublicKey);
  return _open(
    key: await deriveWrapKey(shared, info),
    nonce: wrap.nonce,
    sealed: wrap.sealedKey,
    aad: info,
    what: 'member wrap',
  );
}

/// Seal [contentKey] under the founding identity's master wrap key.
///
/// One per `(Workspace, epoch)`, and the recovery route for the whole key
/// plane. No server can check that the key used here is the right one — 72
/// bytes sealed under the wrong key hash exactly as well as 72 under the right
/// one — so the obligation lands on the author of the `rotate`, which is why
/// [WorkspaceKeyPlane.rotate] is where this library enforces it.
Future<Uint8List> mintEscrowWrap({
  required String namespace,
  required List<int> workspaceId,
  required int epoch,
  required List<int> contentKey,
  required List<int> masterWrapKey,
  required List<int> nonce,
}) async {
  _expect(contentKey, epochKeyLen, 'epoch key');
  _expect(masterWrapKey, epochKeyLen, 'master wrap key');
  _expect(nonce, wrapNonceLen, 'wrap nonce');
  final info = escrowWrapInfo(
    namespace: namespace,
    workspaceId: workspaceId,
    epoch: epoch,
  );
  final box = await _aead.encrypt(
    contentKey,
    secretKey: SecretKey(masterWrapKey),
    nonce: nonce,
    aad: info,
  );
  return Uint8List.fromList(
    <int>[...nonce, ...box.cipherText, ...box.mac.bytes],
  );
}

/// Open an escrow wrap under the master wrap key.
Future<Uint8List> openEscrowWrap({
  required String namespace,
  required List<int> escrowWrap,
  required List<int> workspaceId,
  required int epoch,
  required List<int> masterWrapKey,
}) async {
  if (escrowWrap.length != escrowWrapLen) {
    throw RefusedException(
      Refusal.malformedWrap,
      'an escrow wrap is $escrowWrapLen bytes, got ${escrowWrap.length}',
    );
  }
  final bytes = Uint8List.fromList(escrowWrap);
  return _open(
    key: SecretKey(masterWrapKey),
    nonce: Uint8List.sublistView(bytes, 0, wrapNonceLen),
    sealed: Uint8List.sublistView(bytes, wrapNonceLen),
    aad: escrowWrapInfo(
      namespace: namespace,
      workspaceId: workspaceId,
      epoch: epoch,
    ),
    what: 'escrow wrap',
  );
}

/// `keywrap_digest = SHA-256(framed(<ns>/keywrap-digest/v1, epoch ‖ count ‖
/// for each sorted entry: member_id ‖ kex_key_id ‖ SHA-256(wrap) ‖
/// SHA-256(escrow_wrap)))`.
///
/// The sort key is the **raw 16-byte member id, then the raw 8-byte key id,
/// compared as unsigned bytes** — not the UUID text, and emphatically not the
/// base64 spelling, whose alphabet is not monotonic in byte value.
///
/// Sorting at all is what makes the digest describe the *set* rather than the
/// upload order the server could shuffle. Getting the order wrong is the worst
/// available failure: `keywrap_digest_mismatch` is deterministic, a
/// well-behaved client terminalises it, and the Workspace becomes permanently
/// unrotatable. `vectors/keyplane.json` carries a set built so the correct
/// order disagrees with the three an implementation might reach for by
/// accident.
Uint8List keywrapDigest({
  required String namespace,
  required int epoch,
  required List<MemberWrap> memberWraps,
  required List<int> escrowWrap,
}) {
  final sorted = sortWrapSet(memberWraps);
  final parts = <List<int>>[_u32(epoch), _u32(sorted.length)];
  for (final w in sorted) {
    parts
      ..add(w.memberId)
      ..add(w.kexKeyId)
      ..add(crypto.sha256(w.wrap));
  }
  parts.add(crypto.sha256(escrowWrap));
  return crypto.sha256(
    crypto.framed('$namespace/keywrap-digest/v1', parts),
  );
}

/// The wrap set in digest order: raw member id, then raw key id, unsigned.
///
/// A `Uint8List` element is already an unsigned byte in Dart, so comparing the
/// elements is the unsigned comparison the specification asks for. The hazard
/// the document warns about — a UUID type that compares two *signed* 64-bit
/// halves and inverts any pair whose top bit differs — is avoided by never
/// forming those halves, rather than by correcting for them.
List<MemberWrap> sortWrapSet(List<MemberWrap> wraps) {
  final out = List<MemberWrap>.of(wraps);
  out.sort((a, b) {
    final byMember = _compareUnsigned(a.memberId, b.memberId);
    return byMember != 0 ? byMember : _compareUnsigned(a.kexKeyId, b.kexKeyId);
  });
  return out;
}

int _compareUnsigned(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length.compareTo(b.length);
}

/// What a `rotate` commits to and then publishes.
class Rotation {
  const Rotation({
    required this.epoch,
    required this.memberWraps,
    required this.escrowWrap,
    required this.keywrapDigest,
  });

  final int epoch;

  /// In digest order, because that is the order the digest describes and the
  /// order `PUT …/keywraps` is checked against.
  final List<MemberWrap> memberWraps;

  final Uint8List escrowWrap;

  /// Computed **before** the `rotate` is signed: the signed log commits to the
  /// set, and only then is the set uploaded. That ordering is the whole reason
  /// the server cannot curate the set — omitting a device to lock it out, or
  /// adding one to let an attacker in.
  final Uint8List keywrapDigest;
}

/// Who a wrap is being minted for.
class WrapTarget {
  const WrapTarget({
    required this.memberId,
    required this.kexPublicKey,
    required this.ephemeralPrivateKey,
    required this.nonce,
  });

  final List<int> memberId;
  final List<int> kexPublicKey;

  /// Fresh per wrap in a real minting; a parameter here so the vectors can be
  /// reproduced exactly.
  final List<int> ephemeralPrivateKey;
  final List<int> nonce;
}

/// One Workspace's view of the key plane, as a device holds it.
///
/// The device-side obligations the server cannot check live here, because there
/// is nowhere else they can live.
class WorkspaceKeyPlane {
  WorkspaceKeyPlane({
    required this.namespace,
    required List<int> workspaceId,
    List<int>? foundingMasterWrapKey,
    this.epochZeroIsKeyed = false,
  })  : workspaceId = _copy(workspaceId, 16, 'workspace_id'),
        _masterWrapKey = foundingMasterWrapKey == null
            ? null
            : _copy(foundingMasterWrapKey, epochKeyLen, 'master wrap key');

  final String namespace;
  final Uint8List workspaceId;

  /// Whether this Workspace was keyed from epoch 0.
  ///
  /// Part of the positional downgrade test: where epoch 0 is keyed, cleartext
  /// content is a downgrade at *any* position, not only after the first
  /// `rotate`.
  final bool epochZeroIsKeyed;

  final Map<int, Uint8List> _keys = <int, Uint8List>{};
  Uint8List? _masterWrapKey;

  /// The epoch at which this Workspace first rotated, once the reader has seen
  /// it. Null until then.
  int? firstRotateAtSeq;

  /// Whether this device holds the founding identity's master wrap key.
  bool get holdsMasterWrapKey => _masterWrapKey != null;

  /// Learn the master wrap key — from a vault record, during a ceremony.
  ///
  /// Deliberately not derived from Root. `CONF-CLI-014` is the property that
  /// falls out of that: after a `root_handover` and the vault re-write that
  /// follows it, every escrow wrap minted before the handover still opens,
  /// because the key that sealed them never moved.
  void learnMasterWrapKey(List<int> key) {
    _masterWrapKey = _copy(key, epochKeyLen, 'master wrap key');
  }

  void addEpochKey(int epoch, List<int> key) {
    _keys[epoch] = _copy(key, epochKeyLen, 'epoch key');
  }

  Uint8List? epochKey(int epoch) => _keys[epoch];

  /// The newest epoch this device holds a key for, or null if it holds none.
  int? get newestEpoch =>
      _keys.isEmpty ? null : _keys.keys.reduce((a, b) => a > b ? a : b);

  /// The epoch a new op is sealed at: the newest key held.
  ///
  /// `CONF-CLI-020`. Writing at a lower epoch is legal only to drain ops
  /// already signed when the rotation landed — which is why this getter names
  /// the epoch for *new* ops and nothing else decides it.
  int get epochForNewOps {
    final newest = newestEpoch;
    if (newest == null) {
      throw StateError('this device holds no epoch key, so it cannot seal');
    }
    return newest;
  }

  /// Build a rotation to [toEpoch]: every member wrap, the escrow wrap, and the
  /// digest to put in the signed `rotate`.
  ///
  /// **Refuses without the founding master wrap key** (`CONF-CLI-019`). No
  /// server can check this and none ever will: a wrap sealed under a key the
  /// client invented is accepted, committed, and served back, and is
  /// indistinguishable from a good one until somebody takes the recovery route
  /// months later and it does not open. Delegation does not relieve it — a
  /// delegate holds a *signing* key, and an escrow wrap is a sealing.
  Future<Rotation> rotate({
    required int toEpoch,
    required List<int> contentKey,
    required List<WrapTarget> members,
    required List<int> escrowNonce,
  }) async {
    final masterWrapKey = _masterWrapKey;
    if (masterWrapKey == null) {
      throw StateError(
        'a device that does not hold the founding master wrap key MUST NOT '
        'author a rotate: the escrow wrap it sealed would open for nobody, '
        'and no server can detect that',
      );
    }
    final seen = <String>{};
    for (final m in members) {
      if (!seen.add(_hex(m.memberId))) {
        throw ArgumentError(
          'two wraps for one device in one set: ${_hex(m.memberId)}',
        );
      }
    }
    final wraps = <MemberWrap>[];
    for (final m in members) {
      wraps.add(
        await mintMemberWrap(
          namespace: namespace,
          workspaceId: workspaceId,
          epoch: toEpoch,
          contentKey: contentKey,
          memberId: m.memberId,
          kexPublicKey: m.kexPublicKey,
          ephemeralPrivateKey: m.ephemeralPrivateKey,
          nonce: m.nonce,
        ),
      );
    }
    final escrowWrap = await mintEscrowWrap(
      namespace: namespace,
      workspaceId: workspaceId,
      epoch: toEpoch,
      contentKey: contentKey,
      masterWrapKey: masterWrapKey,
      nonce: escrowNonce,
    );
    final sorted = sortWrapSet(wraps);
    return Rotation(
      epoch: toEpoch,
      memberWraps: sorted,
      escrowWrap: escrowWrap,
      keywrapDigest: keywrapDigest(
        namespace: namespace,
        epoch: toEpoch,
        memberWraps: sorted,
        escrowWrap: escrowWrap,
      ),
    );
  }

  /// Check a served wrap set against the digest the signed `rotate` committed
  /// to, refusing on mismatch.
  ///
  /// The client does this for the same reason the server does: the set is not
  /// trustworthy because the server served it, it is trustworthy because it
  /// hashes to a value somebody signed.
  void checkWrapSet({
    required int epoch,
    required List<MemberWrap> memberWraps,
    required List<int> escrowWrap,
    required List<int> committedDigest,
  }) {
    final got = keywrapDigest(
      namespace: namespace,
      epoch: epoch,
      memberWraps: memberWraps,
      escrowWrap: escrowWrap,
    );
    if (_hex(got) != _hex(committedDigest)) {
      throw RefusedException(
        Refusal.keywrapDigestMismatch,
        'epoch $epoch: the served set hashes to ${_hex(got)}, and the signed '
        'rotate committed to ${_hex(committedDigest)}',
      );
    }
  }

  /// Seal a padded body under the epoch key, suite `0x01`.
  ///
  /// The nonce is the header's own, at offset 134, and the associated data is
  /// the **literal 158 header bytes**. Binding the header that way means the
  /// suite, the epoch and the nonce are all covered with no second binding to
  /// keep in step: change any header byte and the body no longer opens.
  Future<Uint8List> sealBody({
    required List<int> header,
    required List<int> paddedBody,
    required int epoch,
  }) async {
    final key = _keys[epoch];
    if (key == null) {
      throw StateError('no epoch key for epoch $epoch');
    }
    final h = _header(header);
    final box = await _aead.encrypt(
      paddedBody,
      secretKey: SecretKey(key),
      nonce: _nonceOf(h),
      aad: h,
    );
    return Uint8List.fromList(<int>[...box.cipherText, ...box.mac.bytes]);
  }

  /// Open a sealed body, returning the padded plaintext.
  ///
  /// Raises [Refusal.aeadFailure] when it does not authenticate. Note what that
  /// means at this point in the sequence: the signature is taken over the
  /// *sealed* bytes, so tampered ciphertext has already failed the signature
  /// check. Reaching here with a body that will not open means bytes the author
  /// really signed that still will not decrypt — a different diagnosis, which
  /// is why it is a different code.
  Future<Uint8List> openBody({
    required List<int> header,
    required List<int> sealedBody,
    required int epoch,
  }) async {
    final key = _keys[epoch];
    if (key == null) {
      throw RefusedException(
        Refusal.aeadFailure,
        'this device holds no key for epoch $epoch',
      );
    }
    if (sealedBody.length < tagLen) {
      throw RefusedException(
        Refusal.malformedEnvelope,
        'a sealed body carries at least a $tagLen-byte tag',
      );
    }
    final h = _header(header);
    return _open(
      key: SecretKey(key),
      nonce: _nonceOf(h),
      sealed: Uint8List.fromList(sealedBody),
      aad: h,
      what: 'body at epoch $epoch',
    );
  }

  /// The positional downgrade test: may an **opaque** op (bit 7 clear) at suite
  /// `0x00` stand at this position?
  ///
  /// `CONF-CLI-006`. The test has to be positional because the epoch field
  /// cannot carry it: an unsealed op carries `key_epoch` 0 by rule, so asking
  /// *is this an epoch I hold a key for* only ever asks about epoch 0 — and a
  /// Workspace that shipped plaintext and later rotated `0 → 1` has no epoch-0
  /// key at all. Every cleartext op written after that rotation would pass as
  /// pre-encryption history, which is exactly the deployment the spec blesses
  /// and exactly the one an attacker would forge.
  void checkNotADowngrade({
    required int opClass,
    required int suite,
    required int atSeq,
  }) {
    if (serverReads(opClass) || suite != suiteNone) return;
    final first = firstRotateAtSeq;
    final afterFirstRotate = first != null && atSeq > first;
    if (epochZeroIsKeyed || afterFirstRotate) {
      throw RefusedException(
        Refusal.plaintextAtEncryptedEpoch,
        epochZeroIsKeyed
            ? 'epoch 0 is keyed here, so cleartext is a downgrade at any '
                'position'
            : 'seq $atSeq is after the first rotate at seq $first',
      );
    }
  }
}

Uint8List _header(List<int> header) {
  if (header.length != headerLen) {
    throw ArgumentError(
      'the associated data is the literal $headerLen header bytes, '
      'got ${header.length}',
    );
  }
  return Uint8List.fromList(header);
}

Uint8List _nonceOf(Uint8List header) =>
    Uint8List.sublistView(header, 134, headerLen);

Future<Uint8List> _open({
  required SecretKey key,
  required Uint8List nonce,
  required Uint8List sealed,
  required List<int> aad,
  required String what,
}) async {
  final ct = Uint8List.sublistView(sealed, 0, sealed.length - tagLen);
  final mac = Uint8List.sublistView(sealed, sealed.length - tagLen);
  try {
    final clear = await _aead.decrypt(
      SecretBox(ct, nonce: nonce, mac: Mac(mac)),
      secretKey: key,
      aad: aad,
    );
    return Uint8List.fromList(clear);
  } on SecretBoxAuthenticationError {
    throw RefusedException(Refusal.aeadFailure, '$what did not authenticate');
  }
}

Uint8List _u32(int v) {
  if (v < 0 || v > 0xFFFFFFFF) {
    throw ArgumentError('not a u32: $v');
  }
  final out = Uint8List(4);
  ByteData.sublistView(out).setUint32(0, v);
  return out;
}

void _expect(List<int> b, int n, String what) {
  if (b.length != n) {
    throw ArgumentError('$what is $n bytes, got ${b.length}');
  }
}

Uint8List _copy(List<int> b, int n, String what) {
  _expect(b, n, what);
  return Uint8List.fromList(b);
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
