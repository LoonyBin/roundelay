/// The protocol's cryptographic constructions, implemented from the
/// specification.
///
/// Written from `docs/`, not ported from `wire/` or from
/// `tests/conformance/roundelay/crypto.py`, for the reason that file gives: a
/// third implementation that shared a codec with the first two could not catch
/// a framing bug, because the error would cancel out on every side and every
/// test would still pass. What proves something is independent implementations
/// agreeing on the frozen vectors in `vectors/`.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as c;
import 'package:cryptography/cryptography.dart';

/// `framed(domain, ...parts)` = `[1 byte: len(domain)] [domain] [rest]`.
///
/// The length prefix is what makes the construction injective. Plain
/// concatenation is not: with a varying namespace, `acme` + `/op/v1` and
/// `acme/op` + `/v1` are the same bytes. `vectors/framing.json` carries that
/// exact collision pair; an implementation whose two answers match has dropped
/// the prefix.
Uint8List framed(String domain, [List<List<int>> parts = const []]) {
  final raw = Uint8List.fromList(domain.codeUnits);
  if (raw.isEmpty || raw.length > 255) {
    throw ArgumentError('domain must be 1-255 bytes, got ${raw.length}');
  }
  final out = BytesBuilder(copy: false)
    ..addByte(raw.length)
    ..add(raw);
  for (final p in parts) {
    out.add(p);
  }
  return out.toBytes();
}

/// SHA-256 over the complete envelope bytes, unframed.
///
/// The one construction in the wire format that is not domain-framed: it
/// identifies bytes, it does not authenticate them.
Uint8List envelopeHash(List<int> envelope) => _sha256(envelope);

/// Bare SHA-256 over a control op's unpacked payload bytes — not the envelope,
/// and not a re-serialisation of the parsed payload.
Uint8List payloadHash(List<int> payload) => _sha256(payload);

/// `key_id` = the first 8 bytes of SHA-256 over a public key.
Uint8List keyId(List<int> publicKey) =>
    Uint8List.sublistView(_sha256(publicKey), 0, 8);

Uint8List _sha256(List<int> data) =>
    Uint8List.fromList(c.sha256.convert(data).bytes);

/// A derived Workspace id: `uuid8(NS, root_pk)`.
///
///     d  = SHA-256( namespace 16B || root_pk 32B )
///     id = d[0..16], octet 6 <- 0x80 | (octet 6 & 0x0F)
///                    octet 8 <- 0x80 | (octet 8 & 0x3F)
///
/// The name is the 32 raw bytes of the key, never a spelling of them: a textual
/// identifier has spellings, and two peers that spell it differently derive
/// different Workspaces and never converge.
Uint8List uuid8(List<int> namespace, List<int> rootPublicKey) {
  if (namespace.length != 16 || rootPublicKey.length != 32) {
    throw ArgumentError('uuid8 takes a 16-byte namespace and a 32-byte key');
  }
  final d = Uint8List.sublistView(
    _sha256(<int>[...namespace, ...rootPublicKey]),
    0,
    16,
  );
  final out = Uint8List.fromList(d);
  out[6] = 0x80 | (out[6] & 0x0F);
  out[8] = 0x80 | (out[8] & 0x3F);
  return out;
}

/// Ed25519 verification.
///
/// Returns `false` rather than throwing on every failure mode — a malformed
/// key, a wrong-length signature, a good signature over other bytes. A pulling
/// client refuses on all of them identically, so they must not be
/// distinguishable to its caller by whether an exception escaped.
Future<bool> verify(
  List<int> publicKey,
  List<int> message,
  List<int> signature,
) async {
  if (publicKey.length != 32 || signature.length != 64) return false;
  try {
    return await Ed25519().verify(
      message,
      signature: Signature(
        signature,
        publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
      ),
    );
  } catch (_) {
    return false;
  }
}

/// Ed25519 signing from a 32-byte private seed.
///
/// Present so the library can generate the vectors it checks itself against,
/// and so a test can build an envelope that *should* fail verification.
Future<Uint8List> sign(List<int> privateSeed, List<int> message) async {
  final keyPair = await Ed25519().newKeyPairFromSeed(privateSeed);
  final signature = await Ed25519().sign(message, keyPair: keyPair);
  return Uint8List.fromList(signature.bytes);
}

/// The Ed25519 public key for a 32-byte private seed.
Future<Uint8List> ed25519Public(List<int> privateSeed) async {
  final keyPair = await Ed25519().newKeyPairFromSeed(privateSeed);
  final pk = await keyPair.extractPublicKey();
  return Uint8List.fromList(pk.bytes);
}
