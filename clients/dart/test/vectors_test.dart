/// The frozen vectors, checked against a third implementation.
///
/// `vectors/README.md`: *a diff in them is a change to the protocol, not to a
/// program.* These tests are the Dart client's half of that contract. They run
/// before anything else in the package for the same reason
/// `tests/conformance/test_vectors.py` does — a client that disagrees with the
/// corpus about what bytes mean cannot be trusted about anything built on top.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as c;
import 'package:roundelay/roundelay.dart';
import 'package:test/test.dart';

/// The repository's `vectors/` directory, from `clients/dart/`.
final _vectorsDir = Directory('../../vectors');

Map<String, dynamic> _load(String name) {
  final f = File('${_vectorsDir.path}/$name');
  if (!f.existsSync()) {
    throw StateError(
      'vector file not found: ${f.absolute.path}. '
      'Tests must run with clients/dart as the working directory.',
    );
  }
  return json.decode(f.readAsStringSync()) as Map<String, dynamic>;
}

Uint8List _hexDecode(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _hexEncode(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

String _sha256Hex(List<int> b) => _hexEncode(c.sha256.convert(b).bytes);

/// Payload filler of length [n]: the bytes `i mod 251`.
///
/// 251 rather than 256 so the pattern never aligns with a size class and hides
/// an off-by-one in the padding.
Uint8List _filler(int n) =>
    Uint8List.fromList(List<int>.generate(n, (i) => i % 251));

/// The 16 raw bytes of a UUID's canonical text.
Uint8List _uuidBytes(String text) => _hexDecode(text.replaceAll('-', ''));

void main() {
  group('framing.json — framed(domain, rest)', () {
    final v = _load('framing.json');
    final cases = (v['cases'] as List).cast<Map<String, dynamic>>();

    for (final k in cases) {
      test('${k['name']}', () {
        final got = framed(k['domain'] as String, [
          _hexDecode(k['rest_hex'] as String),
        ]);
        expect(_hexEncode(got), k['framed_hex']);
        expect(got[0], k['domain_len'],
            reason: 'the first byte is the domain length');
      });
    }

    test('the collision pair stays distinct — the prefix is not dropped', () {
      final a = cases.firstWhere((k) => k['name'] == 'collision_a');
      final b = cases.firstWhere((k) => k['name'] == 'collision_b');
      // Without the length prefix these two concatenate to identical bytes.
      expect(
        (a['domain'] as String) +
            utf8.decode(_hexDecode(a['rest_hex'] as String)),
        (b['domain'] as String) +
            utf8.decode(_hexDecode(b['rest_hex'] as String)),
        reason: 'the vector pair must actually collide under concatenation, '
            'or this test proves nothing',
      );
      expect(a['framed_hex'], isNot(b['framed_hex']));
    });

    test('a domain outside 1-255 bytes is refused', () {
      expect(() => framed(''), throwsArgumentError);
      expect(() => framed('a' * 256), throwsArgumentError);
    });
  });

  group('keyid.json — key_id derivation', () {
    final v = _load('keyid.json');
    for (final k in (v['cases'] as List).cast<Map<String, dynamic>>()) {
      test('${k['label']} (${k['kind']})', () {
        final pk = base64.decode(k['public_key_b64'] as String);
        final id = keyId(pk);
        expect(_hexEncode(id), k['key_id_hex']);
        expect(base64.encode(id), k['key_id_b64']);
        expect(id.length, 8);
      });
    }
  });

  group('uuid8.json — derived Workspace ids', () {
    final v = _load('uuid8.json');
    for (final k in (v['cases'] as List).cast<Map<String, dynamic>>()) {
      test('${k['namespace']} x ${k['root_label']}', () {
        final ns = _uuidBytes(k['namespace'] as String);
        final rootPk = base64.decode(k['root_pk_b64'] as String);

        expect(_sha256Hex(<int>[...ns, ...rootPk]), k['sha256_of_preimage_hex'],
            reason: 'the preimage is namespace || root_pk, raw bytes');

        final id = uuid8(ns, rootPk);
        expect(_hexEncode(id),
            _hexEncode(_uuidBytes(k['workspace_id'] as String)));
        expect(id[6] >> 4, k['version_nibble']);
        expect(id[8] >> 6, k['variant_bits']);
      });
    }

    test('a namespace or key of the wrong length is refused', () {
      expect(() => uuid8(Uint8List(15), Uint8List(32)), throwsArgumentError);
      expect(() => uuid8(Uint8List(16), Uint8List(31)), throwsArgumentError);
    });
  });

  group('domains.json — which domain a class signs under', () {
    final v = _load('domains.json');
    final ns = v['namespace'] as String;
    const extName = 'retention-sweep';

    for (final k
        in (v['op_class_to_domain'] as List).cast<Map<String, dynamic>>()) {
      final opClass = int.parse(k['op_class'] as String);
      test('class $opClass -> ${k['domain']}', () {
        expect(opDomain(ns, opClass, extName), k['domain']);
      });
    }

    test('the ext family is exactly the two-top-bits-set range', () {
      expect(isExtension(0xBF), isFalse, reason: '0xBF is the last core class');
      expect(isExtension(0xC0), isTrue);
      expect(isExtension(0xC5), isTrue);
      expect(isExtension(0xFF), isTrue);
    });

    test('bit 7 is what makes a body server-readable', () {
      expect(serverReads(classContent), isFalse);
      expect(serverReads(classReprise), isFalse);
      expect(serverReads(classControl), isTrue);
      expect(serverReads(classPrune), isTrue);
      expect(serverReads(classExtBinding), isTrue);
    });

    test('a client built against another NAME verifies a different domain', () {
      expect(opDomain(ns, 0xC5, 'retention-sweep'),
          isNot(opDomain(ns, 0xC5, 'something-else')));
    });
  });

  group('body.json — the padding ladder', () {
    final v = _load('body.json');
    final spec = v['ladder'] as Map<String, dynamic>;
    final ladder = Ladder(
      classes: (spec['classes'] as List).cast<int>(),
      step: spec['oversize_step'] as int,
    );

    for (final k
        in (v['legal_body_len'] as List).cast<Map<String, dynamic>>()) {
      test('legal_body_len(${k['body_len']}) == ${k['legal']}', () {
        expect(ladder.legalBodyLen(k['body_len'] as int), k['legal']);
      });
    }

    final minLens = v['min_envelope_len'] as Map<String, dynamic>;
    test('min_envelope_len, plaintext and sealed', () {
      expect(ladder.minEnvelopeLen(suiteNone), minLens['suite_0x00']);
      expect(ladder.minEnvelopeLen(suiteEncrypted), minLens['suite_0x01']);
      // The sealed floor is the plaintext floor plus one Poly1305 tag.
      expect(
        (minLens['suite_0x01'] as int) - (minLens['suite_0x00'] as int),
        tagLen,
      );
    });

    for (final k in (v['padding'] as List).cast<Map<String, dynamic>>()) {
      final payloadLen = k['payload_len'] as int;
      test('payload of $payloadLen bytes pads to ${k['body_len']}', () {
        final payload = k.containsKey('payload_hex')
            ? _hexDecode(k['payload_hex'] as String)
            : _filler(payloadLen);
        expect(payload.length, payloadLen);

        final body = ladder.packBody(payload);
        expect(body.length, k['body_len']);
        expect(_hexEncode(body.sublist(0, 16)), k['body_first_16_hex']);
        expect(_sha256Hex(body), k['body_sha256_hex']);

        // Sealing adds a 16-byte Poly1305 tag on top of the padded plaintext.
        expect(body.length + 16, k['sealed_body_len']);

        // And the ladder is invertible.
        expect(_hexEncode(ladder.unpackBody(body)), _hexEncode(payload));
      });
    }

    test('a body that is not a legal size class is refused', () {
      expect(() => ladder.unpackBody(Uint8List(513)), throwsFormatException);
      expect(() => ladder.unpackBody(Uint8List(0)), throwsFormatException);
    });

    test('a declared payload_len that overruns the body is refused', () {
      final body = Uint8List(512);
      ByteData.sublistView(body).setUint32(0, 509);
      expect(() => ladder.unpackBody(body), throwsFormatException);
    });

    test('non-zero padding is refused — it is a covert channel', () {
      final body = ladder.packBody(_filler(8));
      body[body.length - 1] = 1;
      expect(() => ladder.unpackBody(body), throwsFormatException);
    });

    test('the ambiguous ladder is recorded, not implemented against', () {
      final note = v['ambiguous_ladder_note'] as Map<String, dynamic>;
      final ambiguous = Ladder(
        classes: (note['classes'] as List).cast<int>(),
        step: note['oversize_step'] as int,
      );
      // Not a conformance vector: the core does not say which reading is meant.
      // It is pinned only so a change of reading cannot pass unnoticed.
      expect(ambiguous.bodyLen(note['payload_len'] as int),
          note['this_implementation_writes']);
    });
  });

  group('envelope.json — the 158-byte header and the signing input', () {
    final v = _load('envelope.json');
    final geometry = v['geometry'] as Map<String, dynamic>;
    final envelopes = (v['envelopes'] as List).cast<Map<String, dynamic>>();

    test('geometry', () {
      expect(headerLen, geometry['header_len']);
      expect(sigLen, geometry['sig_len']);
      expect(tagLen, geometry['tag_len']);
      expect(overhead, geometry['overhead']);
    });

    test('header field offsets and widths', () {
      var expected = 0;
      for (final f
          in (v['header_offsets'] as List).cast<Map<String, dynamic>>()) {
        expect(f['offset'], expected,
            reason: '${f['field']} must be contiguous with the field before');
        expected += f['size'] as int;
      }
      expect(expected, headerLen, reason: 'the fields must tile the header');
    });

    for (final e in envelopes) {
      final name = e['name'] as String;
      final headerHex = e['header_hex'] as String;
      final raw = base64.decode(e['envelope_b64'] as String);

      group(name, () {
        test('header parses to the documented fields', () {
          final h = Header.parse(_hexDecode(headerHex));
          final want = e['header'] as Map<String, dynamic>;
          expect(h.opClass, want['op_class']);
          expect(h.suite, want['suite']);
          expect(_hexEncode(h.workspaceId),
              _hexEncode(_uuidBytes(want['workspace_id'] as String)));
          expect(h.keyEpoch, want['key_epoch']);
          expect(_hexEncode(h.opId),
              _hexEncode(_uuidBytes(want['op_id'] as String)));
          expect(_hexEncode(h.authorMemberId),
              _hexEncode(_uuidBytes(want['author_member_id'] as String)));
          expect(base64.encode(h.authorKeyId), want['author_key_id_b64']);
          expect(h.authorSeq, want['author_seq']);
          expect(_hexEncode(h.prevAuthorHash), want['prev_author_hash']);
          expect(_hexEncode(h.observedHead), want['observed_head']);
          expect(base64.encode(h.nonce), want['nonce_b64']);
        });

        test('marshal is the inverse of parse, byte for byte', () {
          expect(_hexEncode(Header.parse(_hexDecode(headerHex)).marshal()),
              headerHex);
        });

        test('envelope splits under the v1 geometry', () {
          final env = parseEnvelope(raw);
          expect(raw.length, e['envelope_len']);
          expect(_hexEncode(env.header.marshal()), headerHex);
          expect(env.body.length, raw.length - overhead);
          expect(base64.encode(env.signature), e['signature_b64']);
        });

        test('signing input is framed(domain, header || body)', () {
          final env = parseEnvelope(raw);
          final input = signingInput(
            e['signing_domain'] as String,
            env.header.marshal(),
            env.body,
          );
          expect(_sha256Hex(input), e['signing_input_sha256_hex']);
        });

        test('envelope hash is bare SHA-256 over the whole envelope', () {
          expect(_hexEncode(parseEnvelope(raw).hash), e['envelope_hash_hex']);
        });

        if (e.containsKey('payload_hex') && e['header']['suite'] == 0) {
          test('body unpacks to the documented payload', () {
            final env = parseEnvelope(raw);
            expect(_hexEncode(const Ladder().unpackBody(env.body)),
                e['payload_hex']);
          });
        }

        if (e.containsKey('payload_utf8') && e['header']['suite'] == 0) {
          test('body unpacks to the documented payload', () {
            final env = parseEnvelope(raw);
            final payload = const Ladder().unpackBody(env.body);
            expect(utf8.decode(payload), e['payload_utf8']);
            expect(_sha256Hex(payload), e['payload_sha256_hex'],
                reason: 'payload_hash is bare SHA-256 over the unpacked bytes');
          });
        }
      });
    }

    test('control chain links a control op to the previous payload', () {
      final chain = v['control_chain'] as Map<String, dynamic>;
      // prev_control_hash is bare SHA-256 over the previous control op's
      // unpacked payload bytes — not the envelope, not a re-serialisation.
      expect(
          _hexEncode(payloadHash(utf8.encode(chain['payload_utf8'] as String))),
          chain['prev_control_hash_hex']);
      expect(chain['envelope_hash_is_framed'], isFalse);
    });
  });

  group('CONF-CLI-001 — a client verifies every pulled envelope and refuses',
      () {
    final env = _load('envelope.json');
    final kid = _load('keyid.json');
    final envelopes = (env['envelopes'] as List).cast<Map<String, dynamic>>();

    /// A ring holding every Ed25519 key in the corpus.
    KeyRing fullRing() {
      final ring = KeyRing();
      for (final k in (kid['cases'] as List).cast<Map<String, dynamic>>()) {
        if (k['kind'] == 'ed25519') {
          ring.add(base64.decode(k['public_key_b64'] as String));
        }
      }
      return ring;
    }

    for (final e in envelopes) {
      final name = e['name'] as String;
      final raw = base64.decode(e['envelope_b64'] as String);
      final isExt = (e['header']['op_class'] as int) & 0xC0 == 0xC0;

      test('$name verifies against the key its header names', () async {
        final got = await verifyEnvelope(
          raw,
          keys: fullRing(),
          namespace: 'acme',
          extName: isExt ? 'retention-sweep' : '',
        );
        expect(_hexEncode(got.hash), e['envelope_hash_hex']);
      });

      test('$name is refused when a payload byte is flipped', () async {
        final tampered = Uint8List.fromList(raw);
        // A byte inside the body, past the header and before the signature.
        tampered[headerLen + 8] ^= 0x01;
        expect(
          () => verifyEnvelope(tampered,
              keys: fullRing(),
              namespace: 'acme',
              extName: isExt ? 'retention-sweep' : ''),
          throwsA(isA<RefusedException>()
              .having((x) => x.refusal, 'refusal', Refusal.badSignature)),
        );
      });

      test('$name is refused when a header byte is flipped', () async {
        final tampered = Uint8List.fromList(raw);
        tampered[62] ^= 0x01; // author_seq — inside the signed header
        expect(
          () => verifyEnvelope(tampered,
              keys: fullRing(),
              namespace: 'acme',
              extName: isExt ? 'retention-sweep' : ''),
          throwsA(isA<RefusedException>()
              .having((x) => x.refusal, 'refusal', Refusal.badSignature)),
        );
      });

      test('$name is refused when the signature is flipped', () async {
        final tampered = Uint8List.fromList(raw);
        tampered[tampered.length - 1] ^= 0x01;
        expect(
          () => verifyEnvelope(tampered,
              keys: fullRing(),
              namespace: 'acme',
              extName: isExt ? 'retention-sweep' : ''),
          throwsA(isA<RefusedException>()
              .having((x) => x.refusal, 'refusal', Refusal.badSignature)),
        );
      });
    }

    test('an envelope whose author key is not trusted is refused', () {
      final e = envelopes.first;
      expect(
        () => verifyEnvelope(base64.decode(e['envelope_b64'] as String),
            keys: KeyRing(), namespace: 'acme'),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.unknownKey)),
      );
    });

    test('an envelope shorter than the geometry is refused', () {
      expect(
        () => verifyEnvelope(Uint8List(overhead - 1),
            keys: fullRing(), namespace: 'acme'),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.malformedEnvelope)),
      );
    });

    test('an envelope whose body is not a legal size class is refused', () {
      // Long enough to split, but the body lands off the ladder.
      expect(
        () => verifyEnvelope(Uint8List(overhead + 100),
            keys: fullRing(), namespace: 'acme'),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.malformedEnvelope)),
      );
    });

    test('an extension op verified under the wrong NAME is refused', () {
      final e = envelopes
          .firstWhere((x) => (x['header']['op_class'] as int) & 0xC0 == 0xC0);
      // The signature is good; the domain a differently-built client computes
      // is not. This is the separation working, not a failure.
      expect(
        () => verifyEnvelope(base64.decode(e['envelope_b64'] as String),
            keys: fullRing(), namespace: 'acme', extName: 'something-else'),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.badSignature)),
      );
    });

    test('an op verified under the wrong namespace is refused', () {
      final e = envelopes.first;
      expect(
        () => verifyEnvelope(base64.decode(e['envelope_b64'] as String),
            keys: fullRing(), namespace: 'other'),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.badSignature)),
      );
    });

    test('a key id is a handle, not an authenticator', () {
      // KeyRing re-derives the id rather than believing a supplied one, so a
      // key cannot be filed under an id that is not its own.
      final ring = KeyRing();
      final pk = base64.decode((kid['cases'] as List)
              .cast<Map<String, dynamic>>()
              .firstWhere((k) => k['kind'] == 'ed25519')['public_key_b64']
          as String);
      ring.add(pk);
      expect(ring.lookup(keyId(pk)), isNotNull);
      expect(ring.lookup(Uint8List(8)), isNull);
    });
  });

  group('round trip — sign and verify our own envelope', () {
    test('a locally signed op verifies, and refuses once altered', () async {
      // Not a vector: this proves the library is self-consistent, which is what
      // lets a failing vector test be read as "the corpus disagrees with us"
      // rather than "signing is broken".
      final seed =
          Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 3) % 256));
      final pk = await ed25519Public(seed);

      final header = Header(
        opClass: classContent,
        workspaceId: Uint8List(16),
        authorKeyId: keyId(pk),
        authorSeq: 42,
      ).marshal();
      final body = const Ladder().packBody(utf8.encode('hello roundelay'));
      final raw = await signOp(seed, 'acme/op/v1', header, body);

      final ring = KeyRing()..add(pk);
      final env = await verifyEnvelope(raw, keys: ring, namespace: 'acme');
      expect(env.header.authorSeq, 42);
      expect(
          utf8.decode(const Ladder().unpackBody(env.body)), 'hello roundelay');

      raw[headerLen + 6] ^= 0x01;
      expect(
        () => verifyEnvelope(raw, keys: ring, namespace: 'acme'),
        throwsA(isA<RefusedException>()
            .having((x) => x.refusal, 'refusal', Refusal.badSignature)),
      );
    });
  });
}
