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
import 'refusal.dart';
import 'wire.dart';

export 'refusal.dart' show Refusal, RefusedException;

/// The suites this client serves. v1 defines exactly two.
const Set<int> defaultServedSuites = {suiteNone, suiteEncrypted};

/// The public keys a client trusts, indexed the way the header addresses them.
///
/// The 8-byte `author_key_id` is a lookup handle, never an authenticator: it is
/// derived from the key, so an attacker can compute one for a key of their own.
/// [add] therefore re-derives the id rather than believing a supplied one, and
/// verification still has to check the signature against the key the id
/// resolves to.
///
/// This is the flat, positionless form — the right shape for a reader that has
/// no log to place a key in. A reader that *does* have one owes more than this:
/// `author_key_id` must resolve to the key in force for that Member at the op's
/// **own position**, which is `CONF-CLI-004` and `CONF-CLI-026`, and needs the
/// registration and every `member_amend` to answer.
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

/// Decide whether this client serves the envelope's suite, reading **only** the
/// two selector bytes.
///
/// `CONF-CLI-028`. The body geometry and the signature length are the suite's,
/// so an envelope at an unknown suite has no trustworthy structure beyond byte
/// 1: a client that computed a body boundary, an envelope hash or a signature
/// verdict for one would be computing them from offsets it has no grounds to
/// believe in.
///
/// Which is why this takes the raw bytes and looks at two of them. It reaches a
/// verdict on a two-byte input, and that is the observable form of the
/// requirement — an implementation that peeked further could not.
///
/// The other half of the requirement is that such an envelope is **kept**, not
/// discarded. That part is structural here: nothing in this library mutates or
/// drops the caller's bytes, so the envelope a caller refused is still the
/// envelope it holds. A future suite is a future reader's to open.
void checkSuiteServed(
  List<int> raw, {
  Set<int> servedSuites = defaultServedSuites,
}) {
  if (raw.length < 2) {
    throw const RefusedException(
      Refusal.malformedEnvelope,
      'fewer than the two selector bytes',
    );
  }
  final suite = raw[1];
  if (!servedSuites.contains(suite)) {
    throw RefusedException(
      Refusal.suiteNotServed,
      'suite 0x${suite.toRadixString(16).padLeft(2, '0')} is not served here; '
      'the bytes are kept, not discarded',
    );
  }
}

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
  Set<int> servedSuites = defaultServedSuites,
}) async {
  // The suite gate comes first, on two bytes, before any other offset is
  // trusted. See [checkSuiteServed].
  checkSuiteServed(raw, servedSuites: servedSuites);

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

  checkSuiteInvariants(env.header);

  // `observed_head` has exactly one legal value in v1, and the server judges
  // it no more than it judges the nonce. CONF-CLI-003.
  if (!_allZero(env.header.observedHead)) {
    throw const RefusedException(
      Refusal.illegalFieldValue,
      'observed_head is zero in v1',
    );
  }

  final publicKey = keys.lookup(env.header.authorKeyId);
  if (publicKey == null) {
    throw RefusedException(
      Refusal.untrustedKey,
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

/// The fields that have exactly one legal value at suite `0x00`.
///
/// `CONF-CLI-023`. An unsealed envelope carries a zero `nonce` and a zero
/// `key_epoch` — there is nothing for either to mean without a sealed body —
/// **and the server judges neither**. So a non-zero one reaches a client
/// unchallenged, which makes this the client's to refuse or nobody's.
///
/// Worth being precise about why it matters rather than treating it as
/// tidiness: two unused fields a writer may fill freely, in a log every reader
/// sees identically, is a covert channel — the same objection the padding check
/// answers, in the header instead of the body.
void checkSuiteInvariants(Header header) {
  if (header.suite != suiteNone) return;
  if (header.keyEpoch != 0) {
    throw RefusedException(
      Refusal.illegalFieldValue,
      'key_epoch is ${header.keyEpoch} on an unsealed op, and 0 is its only '
      'legal value at suite 0x00',
    );
  }
  if (!_allZero(header.nonce)) {
    throw const RefusedException(
      Refusal.illegalFieldValue,
      'a non-zero nonce on an unsealed op: nothing uses it, so a writer free '
      'to fill it has a covert channel',
    );
  }
}

bool _allZero(List<int> b) => b.every((x) => x == 0);

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
