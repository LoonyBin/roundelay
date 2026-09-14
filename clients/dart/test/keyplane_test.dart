/// `vectors/keyplane.json`, bound to the key plane.
///
/// The server holds every byte this file constructs and can open none of them.
/// That is the claim content-blindness rests on, so it is checked here by
/// reproducing the frozen wraps byte for byte rather than by round-tripping the
/// library against itself: a round trip agrees with any consistent mistake.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:roundelay/roundelay.dart';
import 'package:test/test.dart';

import 'support.dart';

/// The namespace the corpus was built under — read out of the vectors rather
/// than assumed. `info_hex` opens with `framed`'s length prefix and the domain,
/// so the corpus states its own namespace and a test that hard-coded one could
/// drift from it silently.
String _namespaceFromInfo(String infoHex, String domainSuffix) {
  final bytes = hexDecode(infoHex);
  final domain = utf8.decode(bytes.sublist(1, 1 + bytes[0]));
  if (!domain.endsWith(domainSuffix)) {
    throw StateError('$domain does not end with $domainSuffix');
  }
  return domain.substring(0, domain.length - domainSuffix.length);
}

MemberWrap _wrapOf(Map<String, dynamic> e) => MemberWrap(
      memberId: uuidBytes(e['member_id'] as String),
      kexKeyId: b64(e['kex_key_id_b64'] as String),
      wrap: b64(e['wrap_b64'] as String),
    );

void main() {
  final v = loadVector('keyplane.json');
  final contentKey = b64(v['content_key_b64'] as String);
  final masterWrapKey = b64(v['master_wrap_key_b64'] as String);
  final workspaceId = uuidBytes(v['workspace_id'] as String);
  final epoch = v['epoch'] as int;
  final members = (v['member_wraps'] as List).cast<Map<String, dynamic>>();
  final escrow = v['escrow_wrap'] as Map<String, dynamic>;
  final ns = _namespaceFromInfo(
    escrow['info_hex'] as String,
    '/epoch-key-escrow/v1',
  );

  group('keyplane.json — the HKDF salt', () {
    test('is RFC 5869 default: 32 zero bytes, not a zero-length key', () {
      expect(hexEncode(hkdfSalt), v['hkdf_salt_hex']);
      expect(hkdfSalt.length, 32);
      expect(hkdfSalt.every((b) => b == 0), isTrue);
    });
  });

  group('keyplane.json — member wraps', () {
    for (final m in members) {
      final label = m['label'] as String;

      test('$label: the wrap is $memberWrapLen bytes', () {
        expect(memberWrapLen, m['wrap_len']);
        expect(b64(m['wrap_b64'] as String).length, m['wrap_len']);
      });

      test('$label: the epk is the ephemeral private key\'s own public key',
          () async {
        expect(
          hexEncode(await x25519Public(
              b64(m['ephemeral_private_key_b64'] as String))),
          hexEncode(b64(m['ephemeral_public_key_b64'] as String)),
        );
      });

      test('$label: kex_key_id is derived from the key, not declared', () {
        expect(
          hexEncode(keyId(b64(m['kex_public_key_b64'] as String))),
          hexEncode(b64(m['kex_key_id_b64'] as String)),
        );
      });

      test('$label: info pins the wrap to its one slot', () {
        final info = memberWrapInfo(
          namespace: ns,
          ephemeralPublicKey: b64(m['ephemeral_public_key_b64'] as String),
          workspaceId: workspaceId,
          epoch: epoch,
          memberId: uuidBytes(m['member_id'] as String),
          kexKeyId: b64(m['kex_key_id_b64'] as String),
        );
        expect(hexEncode(info), m['info_hex']);
      });

      test('$label: minting reproduces the frozen wrap byte for byte',
          () async {
        final got = await mintMemberWrap(
          namespace: ns,
          workspaceId: workspaceId,
          epoch: epoch,
          contentKey: contentKey,
          memberId: uuidBytes(m['member_id'] as String),
          kexPublicKey: b64(m['kex_public_key_b64'] as String),
          ephemeralPrivateKey: b64(m['ephemeral_private_key_b64'] as String),
          nonce: b64(m['nonce_b64'] as String),
        );
        expect(hexEncode(got.wrap), hexEncode(b64(m['wrap_b64'] as String)));
        expect(hexEncode(got.kexKeyId),
            hexEncode(b64(m['kex_key_id_b64'] as String)));
        expect(hexEncode(got.ephemeralPublicKey),
            hexEncode(b64(m['ephemeral_public_key_b64'] as String)));
        expect(hexEncode(got.nonce), hexEncode(b64(m['nonce_b64'] as String)));
      });
    }

    // The corpus publishes no device sealing *private* key — a device's is
    // never written down — so opening is driven from a key minted here. What
    // the corpus pins is the ciphertext, and that is checked above.
    test('a wrap opens under the device sealing key it was addressed to',
        () async {
      final kexPrivate = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final kexPublic = await x25519Public(kexPrivate);
      final memberId = uuidBytes(members.first['member_id'] as String);
      final wrap = await mintMemberWrap(
        namespace: ns,
        workspaceId: workspaceId,
        epoch: epoch,
        contentKey: contentKey,
        memberId: memberId,
        kexPublicKey: kexPublic,
        ephemeralPrivateKey:
            b64(members.first['ephemeral_private_key_b64'] as String),
        nonce: b64(members.first['nonce_b64'] as String),
      );
      expect(
        hexEncode(await openMemberWrap(
          namespace: ns,
          wrap: wrap,
          workspaceId: workspaceId,
          epoch: epoch,
          memberId: memberId,
          kexPrivateKey: kexPrivate,
        )),
        hexEncode(contentKey),
      );
    });

    test('the same wrap moved to another slot does not open', () async {
      final kexPrivate = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final kexPublic = await x25519Public(kexPrivate);
      final memberId = uuidBytes(members.first['member_id'] as String);
      final wrap = await mintMemberWrap(
        namespace: ns,
        workspaceId: workspaceId,
        epoch: epoch,
        contentKey: contentKey,
        memberId: memberId,
        kexPublicKey: kexPublic,
        ephemeralPrivateKey:
            b64(members.first['ephemeral_private_key_b64'] as String),
        nonce: b64(members.first['nonce_b64'] as String),
      );

      // Every field of `info` the caller supplies is associated data, so each
      // of these is a different slot and none of them authenticates.
      Future<void> expectRefused(Future<void> Function() body) => expectLater(
            body(),
            throwsA(isA<RefusedException>()
                .having((x) => x.refusal, 'refusal', Refusal.aeadFailure)),
          );

      await expectRefused(() => openMemberWrap(
            namespace: ns,
            wrap: wrap,
            workspaceId: workspaceId,
            epoch: epoch + 1,
            memberId: memberId,
            kexPrivateKey: kexPrivate,
          ));
      await expectRefused(() => openMemberWrap(
            namespace: ns,
            wrap: wrap,
            workspaceId: workspaceId,
            epoch: epoch,
            memberId: uuidBytes(members.last['member_id'] as String),
            kexPrivateKey: kexPrivate,
          ));
      await expectRefused(() => openMemberWrap(
            namespace: 'other',
            wrap: wrap,
            workspaceId: workspaceId,
            epoch: epoch,
            memberId: memberId,
            kexPrivateKey: kexPrivate,
          ));
      await expectRefused(() => openMemberWrap(
            namespace: ns,
            wrap: wrap,
            workspaceId: Uint8List(16),
            epoch: epoch,
            memberId: memberId,
            kexPrivateKey: kexPrivate,
          ));
    });

    test('a wrap of the wrong length is malformed, not an AEAD failure',
        () async {
      final short = _wrapOf(members.first);
      final truncated = MemberWrap(
        memberId: short.memberId,
        kexKeyId: short.kexKeyId,
        wrap: short.wrap.sublist(0, memberWrapLen - 1),
      );
      await expectLater(
        openMemberWrap(
          namespace: ns,
          wrap: truncated,
          workspaceId: workspaceId,
          epoch: epoch,
          memberId: short.memberId,
          kexPrivateKey: Uint8List(32),
        ),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.malformedWrap)),
      );
    });
  });

  group('keyplane.json — the escrow wrap', () {
    test('is $escrowWrapLen bytes', () {
      expect(escrowWrapLen, escrow['wrap_len']);
      expect(b64(escrow['escrow_wrap_b64'] as String).length, escrowWrapLen);
    });

    test('info is the Workspace and the epoch, and nothing else', () {
      expect(
        hexEncode(escrowWrapInfo(
          namespace: ns,
          workspaceId: workspaceId,
          epoch: epoch,
        )),
        escrow['info_hex'],
      );
    });

    test('minting reproduces the frozen escrow wrap byte for byte', () async {
      expect(
        hexEncode(await mintEscrowWrap(
          namespace: ns,
          workspaceId: workspaceId,
          epoch: epoch,
          contentKey: contentKey,
          masterWrapKey: masterWrapKey,
          nonce: b64(escrow['nonce_b64'] as String),
        )),
        hexEncode(b64(escrow['escrow_wrap_b64'] as String)),
      );
    });

    test('the recovery route: it opens under the master wrap key', () async {
      expect(
        hexEncode(await openEscrowWrap(
          namespace: ns,
          escrowWrap: b64(escrow['escrow_wrap_b64'] as String),
          workspaceId: workspaceId,
          epoch: epoch,
          masterWrapKey: masterWrapKey,
        )),
        hexEncode(contentKey),
      );
    });

    test('it does not open at another epoch, or under another key', () async {
      Future<void> expectRefused(Future<void> Function() body) => expectLater(
            body(),
            throwsA(isA<RefusedException>()
                .having((x) => x.refusal, 'refusal', Refusal.aeadFailure)),
          );

      await expectRefused(() => openEscrowWrap(
            namespace: ns,
            escrowWrap: b64(escrow['escrow_wrap_b64'] as String),
            workspaceId: workspaceId,
            epoch: epoch + 1,
            masterWrapKey: masterWrapKey,
          ));
      await expectRefused(() => openEscrowWrap(
            namespace: ns,
            escrowWrap: b64(escrow['escrow_wrap_b64'] as String),
            workspaceId: workspaceId,
            epoch: epoch,
            masterWrapKey: Uint8List(32),
          ));
    });

    test('a wrap of the wrong length never reaches the AEAD', () async {
      await expectLater(
        openEscrowWrap(
          namespace: ns,
          escrowWrap: b64(escrow['escrow_wrap_b64'] as String)
              .sublist(0, escrowWrapLen - 1),
          workspaceId: workspaceId,
          epoch: epoch,
          masterWrapKey: masterWrapKey,
        ),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.malformedWrap)),
      );
    });
  });

  group('keyplane.json — keywrap_digest', () {
    final published = members.map(_wrapOf).toList();
    final escrowWrap = b64(escrow['escrow_wrap_b64'] as String);
    final expected = v['keywrap_digest'] as Map<String, dynamic>;

    test('the set hashes to the frozen digest', () {
      expect(published.length, expected['member_wrap_count']);
      expect(
        hexEncode(keywrapDigest(
          namespace: ns,
          epoch: epoch,
          memberWraps: published,
          escrowWrap: escrowWrap,
        )),
        expected['digest_hex'],
      );
    });

    test('member_wraps is published in digest order', () {
      expect(
        sortWrapSet(published).map((w) => hexEncode(w.memberId)).toList(),
        published.map((w) => hexEncode(w.memberId)).toList(),
      );
    });

    test('it describes the set, so the input order cannot change it', () {
      expect(
        hexEncode(keywrapDigest(
          namespace: ns,
          epoch: epoch,
          memberWraps: published.reversed.toList(),
          escrowWrap: escrowWrap,
        )),
        expected['digest_hex'],
      );
    });

    test('the escrow wrap is inside it', () {
      expect(
        hexEncode(keywrapDigest(
          namespace: ns,
          epoch: epoch,
          memberWraps: published,
          escrowWrap: Uint8List(escrowWrapLen),
        )),
        isNot(expected['digest_hex']),
      );
    });

    test('so is the epoch', () {
      expect(
        hexEncode(keywrapDigest(
          namespace: ns,
          epoch: epoch + 1,
          memberWraps: published,
          escrowWrap: escrowWrap,
        )),
        isNot(expected['digest_hex']),
      );
    });
  });

  group('keyplane.json — the sort key, on a set built to expose it', () {
    final o = v['keywrap_digest_ordering'] as Map<String, dynamic>;
    final entries = (o['entries_in_correct_sort_order'] as List)
        .cast<Map<String, dynamic>>();
    final byLabel = <String, MemberWrap>{
      for (final e in entries) e['label'] as String: _wrapOf(e),
    };
    final orderings = (o['orderings'] as Map<String, dynamic>).map(
      (k, val) => MapEntry(k, (val as List).cast<String>()),
    );
    final correct = orderings['raw_unsigned_bytes_correct']!;
    final escrowWrap = b64(o['escrow_wrap_b64'] as String);
    final orderingEpoch = o['epoch'] as int;

    test('the vector is not vacuous: the wrong orders really are different',
        () {
      for (final name in [
        'base64_spelling_wrong',
        'signed_64bit_halves_wrong'
      ]) {
        expect(orderings[name], isNot(correct),
            reason: '$name must disagree with the correct order, or this '
                'vector proves nothing');
      }
    });

    test('sortWrapSet reaches the raw-unsigned-bytes order', () {
      for (final input in orderings.values) {
        expect(
          sortWrapSet(input.map((l) => byLabel[l]!).toList())
              .map((w) => '${hexEncode(w.memberId)}/${hexEncode(w.kexKeyId)}')
              .toList(),
          correct
              .map((l) => '${hexEncode(byLabel[l]!.memberId)}/'
                  '${hexEncode(byLabel[l]!.kexKeyId)}')
              .toList(),
        );
      }
    });

    test('every input order reaches the one frozen digest', () {
      expect(entries.length, o['member_wrap_count']);
      for (final input in orderings.values) {
        expect(
          hexEncode(keywrapDigest(
            namespace: ns,
            epoch: orderingEpoch,
            memberWraps: input.map((l) => byLabel[l]!).toList(),
            escrowWrap: escrowWrap,
          )),
          o['digest_hex'],
        );
      }
    });
  });

  group('the obligations no server can check', () {
    WorkspaceKeyPlane plane({bool withMasterKey = true}) => WorkspaceKeyPlane(
          namespace: ns,
          workspaceId: workspaceId,
          foundingMasterWrapKey: withMasterKey ? masterWrapKey : null,
        );

    // CONF-CLI-019. A rotate whose escrow wrap was sealed under a key the
    // client invented is accepted, committed and served back, and is
    // indistinguishable from a good one until somebody takes the recovery
    // route months later and it does not open.
    test('a device without the master wrap key MUST NOT author a rotate',
        () async {
      final p = plane(withMasterKey: false);
      expect(p.holdsMasterWrapKey, isFalse);
      await expectLater(
        p.rotate(
          toEpoch: epoch,
          contentKey: contentKey,
          members: const [],
          escrowNonce: b64(escrow['nonce_b64'] as String),
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('rotate reproduces the corpus: same wraps, same digest', () async {
      final r = await plane().rotate(
        toEpoch: epoch,
        contentKey: contentKey,
        members: [
          for (final m in members)
            WrapTarget(
              memberId: uuidBytes(m['member_id'] as String),
              kexPublicKey: b64(m['kex_public_key_b64'] as String),
              ephemeralPrivateKey:
                  b64(m['ephemeral_private_key_b64'] as String),
              nonce: b64(m['nonce_b64'] as String),
            ),
        ],
        escrowNonce: b64(escrow['nonce_b64'] as String),
      );
      expect(
        r.memberWraps.map((w) => hexEncode(w.wrap)).toList(),
        members.map((m) => hexEncode(b64(m['wrap_b64'] as String))).toList(),
      );
      expect(hexEncode(r.escrowWrap),
          hexEncode(b64(escrow['escrow_wrap_b64'] as String)));
      expect(hexEncode(r.keywrapDigest),
          (v['keywrap_digest'] as Map<String, dynamic>)['digest_hex']);
    });

    test('two wraps for one device in one set is rejected at minting time',
        () async {
      final target = WrapTarget(
        memberId: uuidBytes(members.first['member_id'] as String),
        kexPublicKey: b64(members.first['kex_public_key_b64'] as String),
        ephemeralPrivateKey:
            b64(members.first['ephemeral_private_key_b64'] as String),
        nonce: b64(members.first['nonce_b64'] as String),
      );
      await expectLater(
        plane().rotate(
          toEpoch: epoch,
          contentKey: contentKey,
          members: [target, target],
          escrowNonce: b64(escrow['nonce_b64'] as String),
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('a served set that does not hash to the committed digest is refused',
        () {
      final p = plane();
      final published = members.map(_wrapOf).toList();
      final committed = hexDecode((v['keywrap_digest']
          as Map<String, dynamic>)['digest_hex'] as String);

      // The good set passes.
      p.checkWrapSet(
        epoch: epoch,
        memberWraps: published,
        escrowWrap: b64(escrow['escrow_wrap_b64'] as String),
        committedDigest: committed,
      );

      // A set the server curated — one device dropped — does not.
      expect(
        () => p.checkWrapSet(
          epoch: epoch,
          memberWraps: published.sublist(0, 1),
          escrowWrap: b64(escrow['escrow_wrap_b64'] as String),
          committedDigest: committed,
        ),
        throwsA(isA<RefusedException>().having(
            (x) => x.refusal, 'refusal', Refusal.keywrapDigestMismatch)),
      );
    });

    // CONF-CLI-020.
    test('a new op seals at the newest epoch the device holds', () {
      final p = plane();
      expect(() => p.epochForNewOps, throwsA(isA<StateError>()));
      p
        ..addEpochKey(1, contentKey)
        ..addEpochKey(3, contentKey)
        ..addEpochKey(2, contentKey);
      expect(p.epochForNewOps, 3);
      expect(p.newestEpoch, 3);
    });
  });

  group('sealing a body binds the literal header — suite 0x01', () {
    final plane = WorkspaceKeyPlane(namespace: ns, workspaceId: workspaceId)
      ..addEpochKey(epoch, contentKey);
    const ladder = Ladder();
    final header = Header(
      opClass: classContent,
      suite: suiteEncrypted,
      workspaceId: workspaceId,
      keyEpoch: epoch,
      nonce: Uint8List.fromList(List<int>.generate(24, (i) => 0x40 + i)),
    ).marshal();
    final padded = ladder.packBody(utf8.encode('the body the server cannot '
        'read'));

    test('what was sealed comes back', () async {
      final sealed = await plane.sealBody(
          header: header, paddedBody: padded, epoch: epoch);
      expect(sealed.length, padded.length + tagLen);
      final opened = await plane.openBody(
          header: header, sealedBody: sealed, epoch: epoch);
      expect(hexEncode(opened), hexEncode(padded));
      expect(utf8.decode(ladder.unpackBody(opened)),
          'the body the server cannot read');
    });

    test('a single changed header byte and the body no longer opens', () async {
      final sealed = await plane.sealBody(
          header: header, paddedBody: padded, epoch: epoch);
      for (final at in [0, 1, 18, 21, 134, headerLen - 1]) {
        final tampered = Uint8List.fromList(header);
        tampered[at] ^= 0x01;
        await expectLater(
          plane.openBody(header: tampered, sealedBody: sealed, epoch: epoch),
          throwsA(isA<RefusedException>()
              .having((x) => x.refusal, 'refusal', Refusal.aeadFailure)),
          reason: 'header byte $at is inside the associated data',
        );
      }
    });

    test(
        'an epoch this device holds no key for is an AEAD failure, not a crash',
        () async {
      final sealed = await plane.sealBody(
          header: header, paddedBody: padded, epoch: epoch);
      await expectLater(
        plane.openBody(header: header, sealedBody: sealed, epoch: epoch + 9),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.aeadFailure)),
      );
    });

    test('the associated data is the literal 158 bytes, not a prefix of them',
        () async {
      await expectLater(
        plane.sealBody(
          header: header.sublist(0, headerLen - 1),
          paddedBody: padded,
          epoch: epoch,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  // CONF-CLI-006. The test has to be positional: an unsealed op carries
  // key_epoch 0 by rule, so asking "is this an epoch I hold a key for" only
  // ever asks about epoch 0 — and a Workspace that shipped plaintext and then
  // rotated 0 -> 1 holds no epoch-0 key at all.
  group('the positional downgrade test', () {
    test('cleartext before the first rotate stands; after it does not', () {
      final p = WorkspaceKeyPlane(namespace: ns, workspaceId: workspaceId)
        ..firstRotateAtSeq = 50;

      p.checkNotADowngrade(opClass: classContent, suite: suiteNone, atSeq: 49);
      p.checkNotADowngrade(opClass: classContent, suite: suiteNone, atSeq: 50);
      expect(
        () => p.checkNotADowngrade(
            opClass: classContent, suite: suiteNone, atSeq: 51),
        throwsA(isA<RefusedException>().having(
            (x) => x.refusal, 'refusal', Refusal.plaintextAtEncryptedEpoch)),
      );
    });

    test('where epoch 0 is keyed, cleartext is a downgrade at any position',
        () {
      final p = WorkspaceKeyPlane(
        namespace: ns,
        workspaceId: workspaceId,
        epochZeroIsKeyed: true,
      );
      for (final seq in [0, 1, 1000]) {
        expect(
          () => p.checkNotADowngrade(
              opClass: classContent, suite: suiteNone, atSeq: seq),
          throwsA(isA<RefusedException>().having(
              (x) => x.refusal, 'refusal', Refusal.plaintextAtEncryptedEpoch)),
        );
      }
    });

    test('a server-readable op is cleartext by design and never a downgrade',
        () {
      final p = WorkspaceKeyPlane(
        namespace: ns,
        workspaceId: workspaceId,
        epochZeroIsKeyed: true,
      )..firstRotateAtSeq = 1;
      for (final k in [classControl, classPrune, classExtBinding]) {
        expect(serverReads(k), isTrue);
        p.checkNotADowngrade(opClass: k, suite: suiteNone, atSeq: 9999);
      }
    });

    test('a sealed op is not a downgrade whatever its position', () {
      final p = WorkspaceKeyPlane(
        namespace: ns,
        workspaceId: workspaceId,
        epochZeroIsKeyed: true,
      )..firstRotateAtSeq = 1;
      p.checkNotADowngrade(
          opClass: classContent, suite: suiteEncrypted, atSeq: 9999);
    });
  });
}
