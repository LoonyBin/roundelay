/// `vectors/auth.json`, bound to certificates, the device login and the vault.
///
/// These signatures say something different from an envelope's. An envelope
/// signature says *this device sent this*; a certificate signature says *this
/// authority approved this fact*. They come apart because the approver is
/// usually not the sender — Root signs a registration, and the device being
/// registered is what posts it.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:roundelay/roundelay.dart';
import 'package:test/test.dart';

import 'support.dart';

/// The namespace the corpus was built under, read out of the corpus.
String _namespaceOf(String domain, String suffix) {
  if (!domain.endsWith(suffix)) {
    throw StateError('$domain does not end with $suffix');
  }
  return domain.substring(0, domain.length - suffix.length);
}

void main() {
  final v = loadVector('auth.json');
  final cert = v['certificate'] as Map<String, dynamic>;
  final challenge = v['auth_challenge'] as Map<String, dynamic>;
  final vault = v['vault'] as Map<String, dynamic>;
  final ns = _namespaceOf(cert['domain'] as String, '/grant/v1');

  group('auth.json — the certificate', () {
    final certBytes = b64(cert['cert_bytes_b64'] as String);
    final rootKey = b64(cert['root_public_key_b64'] as String);
    final sig = b64(cert['cert_sig_b64'] as String);
    final document = CertificateDocument.values
        .firstWhere((d) => d.document == cert['document']);

    test('the corpus base64 and the corpus text are the same bytes', () {
      expect(utf8.decode(certBytes), cert['cert_bytes_utf8']);
    });

    test('the domain is spelled the way the document spells it', () {
      expect(document.domain(ns), cert['domain']);
    });

    test('the signing input is over the literal bytes', () {
      expect(
        hexEncode(sha256(certInput(ns, document.document, certBytes))),
        cert['signing_input_sha256'],
      );
    });

    // `docs/03-authority.md`: *signed bytes, never re-serialised JSON*. Both
    // re-encodings below parse to the identical document and neither verifies,
    // which is the point — a verifier working from a parsed form is judging
    // something nobody signed, and would accept or reject on whitespace and
    // key order.
    test('re-serialised JSON is a different document and does not verify',
        () async {
      final parsed =
          json.decode(utf8.decode(certBytes)) as Map<String, dynamic>;
      final indented = utf8.encode(
        const JsonEncoder.withIndent('  ').convert(parsed),
      );
      final reordered = utf8.encode(
        json.encode(<String, dynamic>{
          for (final k in parsed.keys.toList().reversed) k: parsed[k],
        }),
      );

      for (final bytes in [indented, reordered]) {
        expect(hexEncode(bytes), isNot(hexEncode(certBytes)),
            reason: 'a re-encoding identical to the original would make this '
                'test prove nothing');
        expect(
          json.decode(utf8.decode(bytes)),
          parsed,
          reason: 'this must still be the same document, only spelled '
              'differently',
        );
        expect(
          await verifyCertificate(
            namespace: ns,
            document: document,
            certBytes: bytes,
            authorityPublicKey: rootKey,
            signature: sig,
          ),
          isFalse,
        );
      }
    });

    test('it verifies under the Root that signed it', () async {
      expect(
        await verifyCertificate(
          namespace: ns,
          document: document,
          certBytes: certBytes,
          authorityPublicKey: rootKey,
          signature: sig,
        ),
        isTrue,
      );
    });

    // The domain is what stops one document's signature verifying as another's.
    test('the same signature presented as another document does not verify',
        () async {
      for (final other in CertificateDocument.values) {
        if (other == document) continue;
        expect(
          await verifyCertificate(
            namespace: ns,
            document: other,
            certBytes: certBytes,
            authorityPublicKey: rootKey,
            signature: sig,
          ),
          isFalse,
          reason: 'a $document accepted as a ${other.document}',
        );
      }
    });

    test('and not under another namespace', () async {
      expect(
        await verifyCertificate(
          namespace: 'other',
          document: document,
          certBytes: certBytes,
          authorityPublicKey: rootKey,
          signature: sig,
        ),
        isFalse,
      );
    });

    test('a flipped byte anywhere is refused', () async {
      for (final at in [0, certBytes.length ~/ 2, certBytes.length - 1]) {
        expect(
          await verifyCertificate(
            namespace: ns,
            document: document,
            certBytes: flipBit(certBytes, at),
            authorityPublicKey: rootKey,
            signature: sig,
          ),
          isFalse,
        );
      }
      for (final at in [0, 32, sigLen - 1]) {
        expect(
          await verifyCertificate(
            namespace: ns,
            document: document,
            certBytes: certBytes,
            authorityPublicKey: rootKey,
            signature: flipBit(sig, at),
          ),
          isFalse,
        );
      }
    });
  });

  // CONF-HAND-005. A Root is not a constant: `root_handover` replaces it, and
  // a log that spans one must still replay. A verifier that used the current
  // Root would refuse every certificate written before the handover — a
  // correct history, rejected.
  group('auth.json — the Root in force at a position', () {
    final certBytes = b64(cert['cert_bytes_b64'] as String);
    final rootKey = b64(cert['root_public_key_b64'] as String);
    final sig = b64(cert['cert_sig_b64'] as String);
    final document = CertificateDocument.values
        .firstWhere((d) => d.document == cert['document']);

    // The outgoing Root is the corpus's; the incoming one is minted here,
    // because a handover is a pair of keys and the corpus freezes one.
    late Uint8List incoming;
    late RootTimeline roots;

    setUp(() async {
      incoming = await ed25519Public(
        Uint8List.fromList(List<int>.generate(32, (i) => 0xA0 ^ i)),
      );
      roots = RootTimeline([
        RootEpoch(fromSeq: 10, rootPublicKey: rootKey),
        RootEpoch(fromSeq: 400, rootPublicKey: incoming),
      ]);
    });

    test('rootAt walks the timeline, and is null below the founding Root', () {
      expect(roots.rootAt(9), isNull);
      expect(hexEncode(roots.rootAt(10)!), hexEncode(rootKey));
      expect(hexEncode(roots.rootAt(399)!), hexEncode(rootKey));
      expect(hexEncode(roots.rootAt(400)!), hexEncode(incoming));
      expect(hexEncode(roots.current), hexEncode(incoming));
    });

    test('the epochs sort, so the caller\'s order does not matter', () {
      final reversed = RootTimeline([
        RootEpoch(fromSeq: 400, rootPublicKey: incoming),
        RootEpoch(fromSeq: 10, rootPublicKey: rootKey),
      ]);
      expect(hexEncode(reversed.rootAt(11)!), hexEncode(rootKey));
      expect(hexEncode(reversed.current), hexEncode(incoming));
    });

    test('a certificate below the handover verifies against the Root there',
        () async {
      await verifyCertificateAtPosition(
        namespace: ns,
        document: document,
        certBytes: certBytes,
        signature: sig,
        roots: roots,
        atSeq: 100,
      );
    });

    test('and is refused against the current one — as a forgery would be',
        () async {
      await expectLater(
        verifyCertificateAtPosition(
          namespace: ns,
          document: document,
          certBytes: certBytes,
          signature: sig,
          roots: roots,
          atSeq: 500,
        ),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.badSignature)),
      );
    });

    // *I hold no Root for this position* is not *these bytes are forged*, and
    // reporting the first as the second sends the reader to the wrong
    // investigation.
    test('below the founding Root it is untrustedKey, not badSignature',
        () async {
      await expectLater(
        verifyCertificateAtPosition(
          namespace: ns,
          document: document,
          certBytes: certBytes,
          signature: sig,
          roots: roots,
          atSeq: 9,
        ),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.untrustedKey)),
      );
    });

    test('a Workspace has at least a founding Root', () {
      expect(() => RootTimeline(const []), throwsA(isA<ArgumentError>()));
    });

    test('a Root public key is 32 bytes', () {
      expect(
        () => RootEpoch(fromSeq: 0, rootPublicKey: Uint8List(31)),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('auth.json — the device login', () {
    final memberId = uuidBytes(challenge['member_id'] as String);
    final nonce = b64(challenge['nonce_b64'] as String);
    final controlKey = b64(challenge['control_public_key_b64'] as String);
    final sig = b64(challenge['signature_b64'] as String);

    test('member_id is the 16 raw bytes, and the corpus says the same', () {
      expect(hexEncode(memberId), challenge['member_id_raw_hex']);
      expect(memberId.length, 16);
    });

    test('the signing input is framed(<ns>/auth-challenge/v1, id || nonce)',
        () {
      expect(
        hexEncode(authChallengeInput(ns, memberId, nonce)),
        challenge['signing_input_hex'],
      );
    });

    test('the frozen answer verifies', () async {
      expect(
        await verifyAuthChallenge(
          namespace: ns,
          memberId: memberId,
          nonce: nonce,
          controlPublicKey: controlKey,
          signature: sig,
        ),
        isTrue,
      );
    });

    test('an answer to another challenge does not', () async {
      final otherNonce = flipBit(nonce, 0);
      expect(
        await verifyAuthChallenge(
          namespace: ns,
          memberId: memberId,
          nonce: otherNonce,
          controlPublicKey: controlKey,
          signature: sig,
        ),
        isFalse,
      );
    });

    test('nor does another member presenting it', () async {
      final otherMember = flipBit(memberId, 15);
      expect(
        await verifyAuthChallenge(
          namespace: ns,
          memberId: otherMember,
          nonce: nonce,
          controlPublicKey: controlKey,
          signature: sig,
        ),
        isFalse,
      );
    });

    // A textual identifier has spellings; raw bytes do not. The hazard is
    // removed rather than mitigated, so the wrong shape is rejected outright.
    test('a textual member_id is refused rather than accommodated', () {
      expect(
        () => verifyAuthChallenge(
          namespace: ns,
          memberId: utf8.encode(challenge['member_id'] as String),
          nonce: nonce,
          controlPublicKey: controlKey,
          signature: sig,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('auth.json — the vault record', () {
    final locator = hexDecode(vault['locator_hex'] as String);
    final blob = b64(vault['blob_b64'] as String);
    final rootKey = b64(vault['root_public_key_b64'] as String);
    final record = VaultRecord(
      locator: locator,
      version: vault['version'] as int,
      blob: blob,
      rootPublicKey: rootKey,
      rootSignature: b64(vault['root_sig_b64'] as String),
    );

    test('the signing input is framed(<ns>/vault/v1, locator || u64 || blob)',
        () {
      expect(
        hexEncode(sha256(vaultSigningInput(ns, record))),
        vault['signing_input_sha256'],
      );
      expect(
        hexEncode(vaultSigningInput(ns, record)),
        hexEncode(vaultInput(ns, locator, vault['version'] as int, blob)),
      );
    });

    test('the frozen record verifies under its Root', () async {
      expect(
        await verifyVaultRecord(
          namespace: ns,
          record: record,
          signingRoot: rootKey,
        ),
        isTrue,
      );
    });

    // The locator is inside the signed bytes, so a record signed for one slot
    // can never be replayed into another.
    test('a record moved to another slot does not verify', () async {
      final moved = VaultRecord(
        locator: flipBit(locator, 0),
        version: record.version,
        blob: blob,
        rootPublicKey: rootKey,
        rootSignature: record.rootSignature,
      );
      expect(
        await verifyVaultRecord(
          namespace: ns,
          record: moved,
          signingRoot: rootKey,
        ),
        isFalse,
      );
    });

    test('nor does a rolled-back version, or an altered blob', () async {
      for (final r in [
        VaultRecord(
          locator: locator,
          version: record.version + 1,
          blob: blob,
          rootPublicKey: rootKey,
          rootSignature: record.rootSignature,
        ),
        VaultRecord(
          locator: locator,
          version: record.version,
          blob: flipBit(blob, 0),
          rootPublicKey: rootKey,
          rootSignature: record.rootSignature,
        ),
      ]) {
        expect(
          await verifyVaultRecord(
            namespace: ns,
            record: r,
            signingRoot: rootKey,
          ),
          isFalse,
        );
      }
    });

    test('a locator is 32 bytes', () {
      expect(
        () => VaultRecord(
          locator: Uint8List(31),
          version: 1,
          blob: blob,
          rootPublicKey: rootKey,
          rootSignature: record.rootSignature,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    // CONF-CLI-008. The served `root_pk` is a claim by whoever stored it; the
    // key recovered from the blob is the one the client derived under its own
    // secret. Believing the former would let the holder of the slot re-pin it.
    test('a served root_pk that is not the recovered Root is a corrupt record',
        () {
      checkVaultRootMatchesRecovered(
        record: record,
        recoveredRootPublicKey: rootKey,
      );
      expect(
        () => checkVaultRootMatchesRecovered(
          record: record,
          recoveredRootPublicKey: flipBit(rootKey, 0),
        ),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.untrustedKey)),
      );
    });
  });

  // CONF-CLI-015. The other order leaves a slot that recovers a Workspace
  // which does not exist — and if the genesis then fails, a recovery route to
  // nothing.
  group('the founding ceremony', () {
    test('the vault slot is not written before the genesis lands', () {
      final c = FoundingCeremony();
      expect(c.genesisLanded, isFalse);
      expect(c.requireGenesisBeforeVaultWrite, throwsA(isA<StateError>()));
      c.genesisDidLand();
      expect(c.genesisLanded, isTrue);
      c.requireGenesisBeforeVaultWrite();
    });
  });
}
