/// Envelope verification — the pulling client's half of the protocol.
///
/// The server deliberately does not verify envelope signatures or author
/// chains: verification belongs to the pulling device, because only it knows
/// which keys it trusts. `docs/01-the-log.md` states that as a design
/// commitment, not an omission. Everything in this file is therefore the only
/// place the property is ever enforced, and `CONF-CLI-001` is the checklist
/// item that says so.
library;

import 'dart:typed_data';

import 'crypto.dart' as crypto;
import 'wire.dart';

/// Why a client refused an envelope.
///
/// These are the client's own codes. They are not in
/// `docs/reference/refusal-codes.md`, which enumerates what a *server* returns
/// over HTTP — a server never returns `bad_signature` because a server never
/// checks one.
enum Refusal {
  /// Fewer bytes than the v1 geometry admits, or a body that is not a legal
  /// size class.
  malformedEnvelope('malformed_envelope'),

  /// The header names an `author_key_id` the client holds no public key for.
  /// Refusing is the whole point: an unknown key is not a trusted key.
  unknownKey('unknown_key'),

  /// The signature does not verify over `framed(domain, header || body)`.
  badSignature('bad_signature'),

  /// `prev_author_hash` does not match the client's own verified head for this
  /// author. `CONF-CLI-002`.
  brokenAuthorChain('broken_author_chain');

  const Refusal(this.code);

  /// The wire spelling, as `conformance/checklist.yaml` writes it.
  final String code;

  @override
  String toString() => code;
}

/// Thrown when a client refuses an envelope. Carries the reason unchanged so a
/// caller can distinguish "I do not know this key" from "this is a forgery".
class RefusedException implements Exception {
  const RefusedException(this.refusal, [this.detail]);

  final Refusal refusal;
  final String? detail;

  @override
  String toString() =>
      'RefusedException(${refusal.code}${detail == null ? '' : ': $detail'})';
}

/// The public keys a client trusts, indexed the way the header addresses them.
///
/// The 8-byte `author_key_id` is a lookup handle, never an authenticator: it is
/// derived from the key, so an attacker can compute one for a key of their own.
/// [add] therefore re-derives the id rather than believing a supplied one, and
/// verification still has to check the signature against the key the id
/// resolves to.
class KeyRing {
  final Map<String, Uint8List> _byKeyId = {};

  /// Trust [publicKey], indexed under its derived `key_id`.
  void add(List<int> publicKey) {
    if (publicKey.length != 32) {
      throw ArgumentError('an Ed25519 public key is 32 bytes');
    }
    _byKeyId[_hex(crypto.keyId(publicKey))] = Uint8List.fromList(publicKey);
  }

  /// The trusted key for [keyId], or `null`.
  Uint8List? lookup(List<int> keyId) => _byKeyId[_hex(keyId)];

  int get length => _byKeyId.length;
}

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// Verify one pulled envelope, and refuse on any failure.
///
/// [namespace] and [extName] select the signing domain: an op below `0xC0`
/// signs under `<ns>/op/v1`, an extension class under `<ns>/ext/<name>/v1`. A
/// client built against one extension NAME cannot verify an op written under
/// another, and that is intended — so [extName] is required to be right, not
/// merely present.
///
/// Returns the parsed [Envelope] on success. Throws [RefusedException]
/// otherwise; it never returns a partially-trusted result, because a caller
/// that receives an envelope object tends to use it.
Future<Envelope> verifyEnvelope(
  List<int> raw, {
  required KeyRing keys,
  required String namespace,
  String extName = '',
  Ladder ladder = const Ladder(),
}) async {
  final Envelope env;
  try {
    env = parseEnvelope(raw);
  } on FormatException catch (e) {
    throw RefusedException(Refusal.malformedEnvelope, e.message);
  }

  // Geometry before cryptography: a body that is not a legal size class was
  // never written by a conforming author, whatever it is signed with.
  //
  // Under suite 0x01 the sealed body carries a 16-byte Poly1305 tag on top of
  // the padded plaintext, so the length class is the body minus the tag.
  final measured = env.header.suite == suiteEncrypted
      ? env.body.length - tagLen
      : env.body.length;
  if (measured < 0 || !ladder.legalBodyLen(measured)) {
    throw RefusedException(
      Refusal.malformedEnvelope,
      'body length ${env.body.length} is not a legal size class',
    );
  }

  final publicKey = keys.lookup(env.header.authorKeyId);
  if (publicKey == null) {
    throw RefusedException(
      Refusal.unknownKey,
      'no trusted key for author_key_id ${_hex(env.header.authorKeyId)}',
    );
  }

  final domain = opDomain(namespace, env.header.opClass, extName);
  final ok = await crypto.verify(
    publicKey,
    signingInput(domain, env.header.marshal(), env.body),
    env.signature,
  );
  if (!ok) {
    throw RefusedException(Refusal.badSignature, 'domain $domain');
  }
  return env;
}
