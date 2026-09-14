/// The refusal vocabulary, checked against the document that defines it.
///
/// `docs/reference/refusal-codes.md` opens with **a code not listed here is not
/// a code**, and carries a *Client codes* table — five codes raised by a device
/// against bytes it pulled, never by the server. A client surfaces a code
/// verbatim (`CONF-CLI-011`), so a library that spelled an internal reason like
/// a protocol code would be putting a word into that channel which the
/// specification says does not exist.
///
/// These tests therefore read the table out of the document rather than
/// restating it in Dart. A copy here would only check Dart against Dart, and
/// would keep passing on the day the document changed — which is the one day it
/// needs to fail.
@TestOn('vm')
library;

import 'package:roundelay/roundelay.dart';
import 'package:test/test.dart';

import 'support.dart';

/// The backticked code in the first column of every row of a markdown table,
/// from [heading] until the next heading.
List<String> _codesUnder(String doc, String heading) {
  final lines = doc.split('\n');
  final start = lines.indexWhere((l) => l.trim() == heading);
  if (start < 0) {
    throw StateError('no "$heading" section in refusal-codes.md');
  }
  final out = <String>[];
  for (var i = start + 1; i < lines.length; i++) {
    final line = lines[i];
    if (line.startsWith('#')) break;
    final m = RegExp(r'^\|\s*`([a-z0-9_]+)`\s*\|').firstMatch(line);
    if (m != null) out.add(m.group(1)!);
  }
  return out;
}

void main() {
  final doc = loadDoc('docs/reference/refusal-codes.md');
  final clientCodes = _codesUnder(doc, '## Client codes');
  final specified = Refusal.values.where((r) => r.specified).toList();
  final local = Refusal.values.where((r) => !r.specified).toList();

  group('the document is being read, not assumed', () {
    test('it states the closed-vocabulary rule this file depends on', () {
      expect(doc, contains('A code not listed here is not a code'));
    });

    test('the Client codes table parsed into something', () {
      expect(clientCodes, isNotEmpty);
      expect(clientCodes, contains('bad_signature'));
    });
  });

  group('the five the document names', () {
    test('are exactly the Refusal values that claim to be specified', () {
      expect(
        specified.map((r) => r.vocabularyCode).toSet(),
        clientCodes.toSet(),
      );
      expect(specified.length, clientCodes.length,
          reason: 'one enum value per code, and no duplicates');
    });

    test('carry the document\'s own spelling as their label', () {
      for (final r in specified) {
        expect(r.label, r.vocabularyCode);
        expect(clientCodes, contains(r.label));
      }
    });
  });

  group('the reasons that are this library\'s own', () {
    test('have no wire spelling at all', () {
      for (final r in local) {
        expect(r.vocabularyCode, isNull,
            reason: '${r.name} is not in the document, so it has no code');
      }
    });

    // The whole hazard: a library-local reason that happened to be spelled
    // like a code would be surfaced verbatim by a client, putting a word into
    // that channel which the specification says does not exist.
    test('are never spelled like any code in the document', () {
      final everyCodeInTheDocument =
          RegExp(r'^\|\s*`([a-z0-9_]+)`\s*\|', multiLine: true)
              .allMatches(doc)
              .map((m) => m.group(1)!)
              .toSet();
      expect(everyCodeInTheDocument.length, greaterThan(clientCodes.length),
          reason: 'the document carries server codes too, or the regex is '
              'matching nothing useful');
      for (final r in local) {
        expect(everyCodeInTheDocument, isNot(contains(r.label)));
      }
    });

    test('still have a stable label, for logs and test failures', () {
      for (final r in local) {
        expect(r.label, r.name);
        expect(r.toString(), r.name);
      }
    });
  });

  group('the pairs the document says must never be merged', () {
    test('unknown_author_key and bad_signature are separate values', () {
      expect(doc, contains('`unknown_author_key` vs `bad_signature`'));
      expect(Refusal.unknownAuthorKey, isNot(Refusal.badSignature));
      expect(Refusal.unknownAuthorKey.vocabularyCode, 'unknown_author_key');
      expect(Refusal.badSignature.vocabularyCode, 'bad_signature');
    });

    // *I hold no key to check these against here* is a positional answer about
    // a device this reader knows. *I have never heard of this key* is what an
    // untrusted author looks like to a reader with no log to place it in. The
    // second is not a protocol code, and must not borrow the first's.
    test('and untrustedKey borrows neither of their spellings', () {
      expect(Refusal.untrustedKey.specified, isFalse);
      expect(Refusal.untrustedKey.vocabularyCode, isNull);
      expect(Refusal.untrustedKey, isNot(Refusal.unknownAuthorKey));
      expect(Refusal.untrustedKey, isNot(Refusal.badSignature));
    });

    test('control_type_not_served is the reader\'s, not the server\'s', () {
      expect(
          doc,
          contains('`control_type_not_served` vs '
              '`unsupported_control_type`'));
      expect(
        Refusal.controlTypeNotServed.vocabularyCode,
        'control_type_not_served',
      );
      // `suite_not_served` would be the same mistake in the other direction:
      // `unsupported_suite` is a server code raised at POST .../ops, and a
      // reader meeting such an envelope is in the opposite position.
      expect(Refusal.suiteNotServed.specified, isFalse);
      expect(doc, contains('`unsupported_suite`'));
    });
  });

  test('a refusal carries its reason and its detail through toString', () {
    const e = RefusedException(Refusal.badSignature, 'a flipped byte');
    expect(e.refusal, Refusal.badSignature);
    expect(e.toString(), 'RefusedException(bad_signature: a flipped byte)');
    expect(
      const RefusedException(Refusal.malformedWrap).toString(),
      'RefusedException(malformedWrap)',
    );
  });
}
