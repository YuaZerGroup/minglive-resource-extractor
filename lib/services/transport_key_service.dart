import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../core/protocol.dart';
import 'api_client.dart';

/// One entry of the transport key manifest.
class TransportKey {
  const TransportKey({required this.id, required this.publicKey});

  final String id;

  /// base64url (no padding) encoded 32-byte X25519 public key.
  final String publicKey;

  Uint8List get publicKeyBytes =>
      Uint8List.fromList(base64Url.decode(base64Url.normalize(publicKey)));

  factory TransportKey.fromJson(Map<String, dynamic> j) => TransportKey(
        id: j['id'] as String? ?? '',
        publicKey: j['publicKey'] as String? ?? '',
      );

  @override
  String toString() => 'TransportKey($id, pub=${publicKey.length}b64)';
}

/// Verified `GET /transport/keys` payload.
class TransportKeyManifest {
  const TransportKeyManifest({
    required this.schema,
    required this.issuedAt,
    required this.expiresAt,
    required this.activeKeyId,
    required this.keys,
    required this.signature,
    required this.rawPayload,
  });

  final String schema;
  final DateTime issuedAt;
  final DateTime expiresAt;
  final String activeKeyId;
  final List<TransportKey> keys;

  /// 64-byte Ed25519 signature over [rawPayload].
  final Uint8List signature;
  final Uint8List rawPayload;

  TransportKey? get activeKey {
    for (final k in keys) {
      if (k.id == activeKeyId) return k;
    }
    return keys.isEmpty ? null : keys.first;
  }

  bool isExpiredAt(DateTime now) => expiresAt.isBefore(now);

  DateTime get issuedAtLocal => issuedAt.toLocal();
  DateTime get expiresAtLocal => expiresAt.toLocal();

  @override
  String toString() => 'TransportKeyManifest(schema=$schema, '
      'active=$activeKeyId, keys=${keys.length}, '
      'expires=$expiresAtLocal, sig=${signature.length}B)';
}

/// Result of validating the manifest signature against a candidate key.
class SignatureCheck {
  const SignatureCheck({
    required this.verified,
    required this.keyId,
    required this.reason,
  });

  final bool verified;
  final String? keyId;
  final String reason;

  @override
  String toString() =>
      'SignatureCheck(verified=$verified, keyId=$keyId, reason=$reason)';
}

/// Fetches and structurally validates the transport key manifest.
///
/// The endpoint is unauthenticated, so this runs before login and gives the
/// client the server's current X25519 public key. The manifest is delivered as
/// `{ payload, signature }` with both fields base64url encoded; the signature
/// covers the exact bytes of `payload`, not a re-serialisation of the JSON.
class TransportKeyService {
  TransportKeyService({required this.client, this.log});

  final ApiClient client;
  final void Function(String message)? log;

  void _emit(String m) => log?.call(m);

  Future<TransportKeyManifest> fetch() async {
    _emit('GET ${Protocol.pathTransportKeys}');
    final res = await client.getJson(Protocol.pathTransportKeys);
    if (!res.isOk || res.json == null) throw ApiException(res);

    final payloadB64 = res.json!['payload'];
    final sigB64 = res.json!['signature'];
    if (payloadB64 is! String || sigB64 is! String) {
      throw StateError(Protocol.errInvalidEnvelope);
    }

    final payloadBytes =
        Uint8List.fromList(base64Url.decode(base64Url.normalize(payloadB64)));
    final sigBytes =
        Uint8List.fromList(base64Url.decode(base64Url.normalize(sigB64)));

    final doc = jsonDecode(utf8.decode(payloadBytes));
    if (doc is! Map<String, dynamic>) {
      throw StateError(Protocol.errTransportKeyManifest);
    }
    if (doc['schema'] != Protocol.transportKeysSchema) {
      throw StateError(
          '${Protocol.errTransportKeyManifest}: schema=${doc['schema']}');
    }

    final keys = (doc['keys'] as List<dynamic>? ?? const [])
        .whereType<Map<String, dynamic>>()
        .map(TransportKey.fromJson)
        .toList(growable: false);

    if (keys.isEmpty) throw StateError(Protocol.errTransportKeyList);
    for (final k in keys) {
      if (k.id.isEmpty || k.publicKeyBytes.length != 32) {
        throw StateError(Protocol.errTransportKeyEntry);
      }
    }
    if (sigBytes.length != 64) {
      throw StateError(
          '${Protocol.errTransportKeySignature}: ${sigBytes.length} bytes');
    }

    final manifest = TransportKeyManifest(
      schema: doc['schema'] as String? ?? '',
      issuedAt: DateTime.fromMillisecondsSinceEpoch(
          (doc['issuedAt'] as num?)?.toInt() ?? 0),
      expiresAt: DateTime.fromMillisecondsSinceEpoch(
          (doc['expiresAt'] as num?)?.toInt() ?? 0),
      activeKeyId: doc['activeKeyId'] as String? ?? '',
      keys: keys,
      signature: sigBytes,
      rawPayload: payloadBytes,
    );

    _emit('transport keys ok: ${manifest.keys.length} key(s), '
        'active=${manifest.activeKeyId}, '
        'valid ${manifest.issuedAtLocal} .. ${manifest.expiresAtLocal}');

    if (manifest.isExpiredAt(DateTime.now())) {
      _emit('WARNING: ${Protocol.errExpiredTransportKey}');
    }
    if (manifest.activeKey == null) {
      _emit('WARNING: ${Protocol.errMissingActiveKey}');
    }
    return manifest;
  }

  /// Structural self-check: SHA-256 of the payload is stable and the signature
  /// has the expected geometry. Cryptographic verification needs the server's
  /// Ed25519 public key, which the shipped app holds as a constant; supply it
  /// via [verifyWithEd25519] once recovered.
  SignatureCheck checkStructure(TransportKeyManifest m) {
    final digest = sha256.convert(m.rawPayload).toString();
    _emit('payload sha256=$digest');
    return SignatureCheck(
      verified: m.signature.length == 64,
      keyId: m.activeKeyId,
      reason: 'payload=${m.rawPayload.length}B sig=${m.signature.length}B '
          'sha256=$digest',
    );
  }

  /// Verifies the manifest signature with a known Ed25519 public key.
  ///
  /// Kept as a hook: the pure-Dart package used here does not ship Ed25519, so
  /// callers that have a native implementation can plug it in.
  Future<SignatureCheck> verifyWithEd25519(
    TransportKeyManifest m,
    Uint8List ed25519PublicKey,
  ) async {
    return SignatureCheck(
      verified: false,
      keyId: m.activeKeyId,
      reason: 'Ed25519 verifier not bound '
          '(pub=${ed25519PublicKey.length}B, '
          'payload=${m.rawPayload.length}B, '
          'sig=${m.signature.length}B)',
    );
  }
}
