/// A reference client library for the roundelay protocol.
///
/// The client-side counterpart to the reference server. Its reason for
/// existing is that the protocol's central security property — *a client
/// verifies every pulled envelope's Ed25519 signature and refuses on failure*,
/// `CONF-CLI-001` — is enforced on the client and nowhere else, by design, and
/// so was tested by nothing until there was a client to test.
///
/// Pure Dart, no Flutter dependency: the wire format is the same on every
/// device, and a library that needed a widget tree could not be run by the Go
/// server's own test corpus.
library;

export 'src/crypto.dart'
    show
        ed25519Public,
        envelopeHash,
        framed,
        keyId,
        payloadHash,
        sign,
        uuid8,
        verify;
export 'src/verify.dart' show KeyRing, Refusal, RefusedException, verifyEnvelope;
export 'src/wire.dart';
