/// The v1 envelope, body framing and the padding ladder.
library;

import 'dart:typed_data';

import 'crypto.dart' as crypto;

const int headerLen = 158;
const int sigLen = 64;
const int overhead = headerLen + sigLen;
const int tagLen = 16;
const int payloadLenPrefix = 4;

const int suiteNone = 0x00;
const int suiteEncrypted = 0x01;

const int classContent = 0x01;
const int classReprise = 0x02;
const int classControl = 0x80;
const int classPrune = 0x81;
const int classExtBinding = 0xBF;

/// Bit 7: set, and the server unpacks the body.
///
/// The class byte is numbered so this is a property of the byte alone — a
/// server decides whether it may read a body without consulting a table it
/// might not have been updated with.
bool serverReads(int opClass) => opClass & 0x80 != 0;

/// An extension class: both top bits set.
bool isExtension(int opClass) => opClass & 0xC0 == 0xC0;

/// Every class below `0xC0` signs under `<ns>/op/v1`.
///
/// An extension class signs under `<ns>/ext/<name>/v1` instead, so a client
/// built against one NAME cannot verify an op written under another — the
/// domain separation is what stops two unrelated extensions that happen to
/// share a class byte from being confused for each other.
String opDomain(String namespace, int opClass, [String extName = '']) =>
    isExtension(opClass) ? '$namespace/ext/$extName/v1' : '$namespace/op/v1';

/// The profile's body size classes and oversize step.
class Ladder {
  const Ladder({this.classes = const [512, 4096], this.step = 4096});

  final List<int> classes;
  final int step;

  /// The body length a payload of [payloadLen] bytes pads up to.
  int bodyLen(int payloadLen) {
    final required = payloadLenPrefix + payloadLen;
    for (final c in classes) {
      if (required <= c) return c;
    }
    // Above the largest class, to the next multiple of the step. The other
    // available reading — the largest class plus a multiple — agrees exactly
    // when the largest class is a multiple of the step, which acme/p1's is.
    // `vectors/body.json` records a ladder where they disagree, deliberately
    // without choosing; this follows the reading the reference server writes.
    return ((required + step - 1) ~/ step) * step;
  }

  /// Whether [n] is a body length this ladder can ever produce.
  bool legalBodyLen(int n) {
    if (classes.contains(n)) return true;
    return n > classes.last && n % step == 0;
  }

  /// The shortest envelope this ladder admits, under [suite].
  int minEnvelopeLen(int suite) {
    final n = headerLen + classes.first + sigLen;
    return suite == suiteEncrypted ? n + tagLen : n;
  }

  /// `[4 byte BE: len(payload)] [payload] [zero padding]`.
  Uint8List packBody(List<int> payload) {
    final n = bodyLen(payload.length);
    final out = Uint8List(n);
    ByteData.sublistView(out).setUint32(0, payload.length);
    out.setRange(payloadLenPrefix, payloadLenPrefix + payload.length, payload);
    return out;
  }

  /// The inverse, refusing every body a conforming writer cannot have produced.
  ///
  /// The padding check is not cosmetic: unchecked trailing bytes are a covert
  /// channel through a log whose whole point is that every reader sees the same
  /// thing.
  Uint8List unpackBody(List<int> body) {
    if (!legalBodyLen(body.length)) {
      throw FormatException(
        'body length ${body.length} is not a legal size class',
      );
    }
    final view = Uint8List.fromList(body);
    final n = ByteData.sublistView(view).getUint32(0);
    if (n > view.length - payloadLenPrefix) {
      throw const FormatException('payload_len overruns the body');
    }
    final end = payloadLenPrefix + n;
    for (var i = end; i < view.length; i++) {
      if (view[i] != 0) {
        throw const FormatException('padding is not all zero');
      }
    }
    return Uint8List.sublistView(view, payloadLenPrefix, end);
  }
}

/// The 158-byte envelope header: canonical order, fixed widths, big-endian
/// integers.
class Header {
  Header({
    required this.opClass,
    this.suite = suiteNone,
    Uint8List? workspaceId,
    this.keyEpoch = 0,
    Uint8List? opId,
    Uint8List? authorMemberId,
    Uint8List? authorKeyId,
    this.authorSeq = 1,
    Uint8List? prevAuthorHash,
    Uint8List? observedHead,
    Uint8List? nonce,
  })  : workspaceId = workspaceId ?? Uint8List(16),
        opId = opId ?? Uint8List(16),
        authorMemberId = authorMemberId ?? Uint8List(16),
        authorKeyId = authorKeyId ?? Uint8List(8),
        prevAuthorHash = prevAuthorHash ?? Uint8List(32),
        observedHead = observedHead ?? Uint8List(32),
        nonce = nonce ?? Uint8List(24);

  final int opClass;
  final int suite;
  final Uint8List workspaceId;
  final int keyEpoch;
  final Uint8List opId;
  final Uint8List authorMemberId;
  final Uint8List authorKeyId;
  final int authorSeq;
  final Uint8List prevAuthorHash;
  final Uint8List observedHead;
  final Uint8List nonce;

  Uint8List marshal() {
    final out = Uint8List(headerLen);
    final view = ByteData.sublistView(out);
    out[0] = opClass;
    out[1] = suite;
    out.setRange(2, 18, workspaceId);
    view.setUint32(18, keyEpoch);
    out.setRange(22, 38, opId);
    out.setRange(38, 54, authorMemberId);
    out.setRange(54, 62, authorKeyId);
    view.setUint64(62, authorSeq);
    out.setRange(70, 102, prevAuthorHash);
    out.setRange(102, 134, observedHead);
    out.setRange(134, 158, nonce);
    return out;
  }

  static Header parse(List<int> raw) {
    if (raw.length < headerLen) {
      throw const FormatException('fewer than 158 bytes, no header');
    }
    final view = Uint8List.fromList(raw);
    final data = ByteData.sublistView(view);
    return Header(
      opClass: view[0],
      suite: view[1],
      workspaceId: Uint8List.sublistView(view, 2, 18),
      keyEpoch: data.getUint32(18),
      opId: Uint8List.sublistView(view, 22, 38),
      authorMemberId: Uint8List.sublistView(view, 38, 54),
      authorKeyId: Uint8List.sublistView(view, 54, 62),
      authorSeq: data.getUint64(62),
      prevAuthorHash: Uint8List.sublistView(view, 70, 102),
      observedHead: Uint8List.sublistView(view, 102, 134),
      nonce: Uint8List.sublistView(view, 134, 158),
    );
  }
}

/// An envelope split under the v1 geometry.
class Envelope {
  const Envelope(this.header, this.body, this.signature, this.raw);

  final Header header;
  final Uint8List body;
  final Uint8List signature;
  final Uint8List raw;

  /// SHA-256 over the complete envelope bytes.
  Uint8List get hash => crypto.envelopeHash(raw);
}

/// Split an envelope. The body length is derived from the total, not declared.
Envelope parseEnvelope(List<int> raw) {
  if (raw.length < overhead) {
    throw const FormatException('shorter than header + signature');
  }
  final view = Uint8List.fromList(raw);
  return Envelope(
    Header.parse(view),
    Uint8List.sublistView(view, headerLen, view.length - sigLen),
    Uint8List.sublistView(view, view.length - sigLen),
    view,
  );
}

/// The bytes an op's signature is taken over: `framed(domain, header || body)`.
///
/// Under suite `0x01` this covers the *sealed* body — the signature commits to
/// the ciphertext, so a relay that cannot read an op still cannot alter it.
Uint8List signingInput(String domain, List<int> header, List<int> body) =>
    crypto.framed(domain, [header, body]);

/// Header, body, and a signature over `framed(domain, header || body)`.
Future<Uint8List> signOp(
  List<int> seed,
  String domain,
  List<int> header,
  List<int> body,
) async {
  final sig = await crypto.sign(seed, signingInput(domain, header, body));
  return Uint8List.fromList(<int>[...header, ...body, ...sig]);
}

/// `framed(<ns>/auth-challenge/v1, member_id || nonce)`.
///
/// `member_id` is the 16 raw bytes, never a textual spelling.
Uint8List authChallengeInput(
  String namespace,
  List<int> memberId,
  List<int> nonce,
) =>
    crypto.framed('$namespace/auth-challenge/v1', [memberId, nonce]);

/// `framed(<ns>/vault/v1, locator || version || blob)`.
Uint8List vaultInput(
  String namespace,
  List<int> locator,
  int version,
  List<int> blob,
) {
  final v = Uint8List(8);
  ByteData.sublistView(v).setUint64(0, version);
  return crypto.framed('$namespace/vault/v1', [locator, v, blob]);
}

/// `framed(<ns>/<document>/v1, the literal certificate bytes)`.
///
/// Never a re-serialisation: a verifier that re-encodes what it parsed is
/// verifying a document nobody signed.
Uint8List certInput(String namespace, String document, List<int> cert) =>
    crypto.framed('$namespace/$document/v1', [cert]);
