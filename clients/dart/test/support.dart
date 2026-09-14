/// Shared helpers for reading the frozen corpus.
///
/// Not a test file — `dart test` only collects `*_test.dart`.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

/// The repository root, from `clients/dart/`.
const String repoRoot = '../..';

/// Read one file from `vectors/`.
Map<String, dynamic> loadVector(String name) {
  final f = File('$repoRoot/vectors/$name');
  if (!f.existsSync()) {
    throw StateError(
      'vector file not found: ${f.absolute.path}. '
      'Tests must run with clients/dart as the working directory.',
    );
  }
  return json.decode(f.readAsStringSync()) as Map<String, dynamic>;
}

/// Read one file from `docs/` or `conformance/`, as text.
///
/// A handful of tests check the library against a table in the specification
/// rather than against a vector. That is deliberate: a closed set — the fifteen
/// domains, the five client codes — is a claim the prose makes, and a test that
/// restated the set in Dart would only check Dart against Dart.
String loadDoc(String path) {
  final f = File('$repoRoot/$path');
  if (!f.existsSync()) {
    throw StateError('document not found: ${f.absolute.path}');
  }
  return f.readAsStringSync();
}

Uint8List b64(String s) => base64.decode(s);

Uint8List hexDecode(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String hexEncode(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

/// The 16 raw bytes of a UUID's canonical text — never a textual spelling.
Uint8List uuidBytes(String text) => hexDecode(text.replaceAll('-', ''));
