import 'dart:convert';
import 'dart:typed_data';

import '../core/protocol.dart';
import '../models/slice_catalog.dart';

/// Builds the signed envelope consumed by the `/features/secure-*` endpoints.
///
/// ## Why this is an interface
///
/// The origin rejects any body that is not a valid envelope with
/// `{"message":"Invalid secure request"}`. Crucially, that string **does not
/// exist anywhere in the client binary** (`Invalid secure request` is absent,
/// while `Invalid secure response`, `Secure response key mismatch`,
/// `Invalid secure session` and `Invalid envelope:` are all present). The
/// client therefore never has to name the failure: it builds the envelope
/// correctly, or it never gets a reply at all.
///
/// The envelope fields recovered from the snapshot are:
///
/// | field         | origin string                |
/// |---------------|------------------------------|
/// | `deviceProof` | `deviceProof`                |
/// | `deviceKeyId` | `deviceKeyId`                |
/// | `serverKeyId` | `serverKeyId`                |
/// | `wrappedKey`  | `wrappedKey`                 |
/// | `sequence`    | `sequence` / `sequence=`     |
/// | `keyId`       | `activeKeyId`                |
/// | `payload`     | `payload`                    |
/// | `signature`   | `signature`                  |
///
/// with supporting constants `minglive-builtin-device-proof-v1`,
/// `minglive-transport-keys-v1`, `MINGLIVE-REMOTE-CONTENT-SALT-v1`,
/// `MINGLIVE-REMOTE-CONTENT-FF1-v3:` and the native channel name
/// `mingliveios/builtin_device_key`.
///
/// The device proof is produced by the native side from a Keychain-backed key
/// pair. Reproducing it therefore requires that key material, which lives on a
/// device and not in the IPA. [EnvelopeBuilder] keeps that boundary explicit.
abstract class EnvelopeBuilder {
  /// Whether this builder can currently produce a usable envelope.
  bool get isReady;

  /// Human readable explanation of why [isReady] is false.
  String get status;

  /// Builds the body for a slice request. Only called when [isReady].
  Map<String, dynamic> buildSliceRequest(SliceResource r, SliceCatalog c);

  /// Builds the body for `POST /features/secure-list`.
  Map<String, dynamic> buildSecureListRequest(SliceCatalog c);

  /// Builds the body for `POST /features/secure-session`.
  Map<String, dynamic> buildSecureSessionRequest(SliceCatalog c);
}

/// Device key material as delivered by `mingliveios/builtin_device_key`.
class DeviceKeyMaterial {
  const DeviceKeyMaterial({
    required this.deviceKeyId,
    required this.privateKey,
    required this.publicKey,
    this.installationId,
    this.sequence = 0,
  });

  final String deviceKeyId;

  /// Raw private key bytes from the Keychain item (`keyPairData`).
  final Uint8List privateKey;

  /// Raw public key bytes (`rawKeyData`).
  final Uint8List publicKey;

  /// Stable install identifier (`minglive.installationId`).
  final String? installationId;

  final int sequence;

  DeviceKeyMaterial copyWith({int? sequence}) => DeviceKeyMaterial(
        deviceKeyId: deviceKeyId,
        privateKey: privateKey,
        publicKey: publicKey,
        installationId: installationId,
        sequence: sequence ?? this.sequence,
      );

  @override
  String toString() => 'DeviceKeyMaterial($deviceKeyId, '
      'priv=${privateKey.length}B, pub=${publicKey.length}B, seq=$sequence)';
}

/// Builder that always reports itself unavailable.
///
/// This is the default so the UI can run the entire local pipeline — catalog
/// load, slice discovery, local SHA-256 verification, size accounting — without
/// pretending the remote half is reachable.
class UnavailableEnvelopeBuilder implements EnvelopeBuilder {
  const UnavailableEnvelopeBuilder(this.reason);

  final String reason;

  @override
  bool get isReady => false;

  @override
  String get status => reason;

  Never _fail() => throw StateError('envelope builder unavailable: $reason');

  @override
  Map<String, dynamic> buildSliceRequest(SliceResource r, SliceCatalog c) =>
      _fail();

  @override
  Map<String, dynamic> buildSecureListRequest(SliceCatalog c) => _fail();

  @override
  Map<String, dynamic> buildSecureSessionRequest(SliceCatalog c) => _fail();
}

/// Builder wired to recovered device key material.
///
/// It emits the exact envelope shape the endpoint expects. Every field is
/// derived deterministically from [material] plus the catalog so the resulting
/// document is byte-stable and audit-able:
///
/// ```
/// {
///   "schema":     "minglive-slice-delivery-v2",
///   "deviceKeyId": ...,
///   "deviceProof": "<base64url>",
///   "keyId":       <catalog.contentKeyId>,
///   "sequence":    <monotonic counter>,
///   "request":     { "resourceId", "path", "cipherSha256", "remoteSize" }
/// }
/// ```
///
/// `deviceProof` must be the signature produced over the request digest with
/// the device private key. [DeviceProofSigner] performs that step when a signer
/// has been attached; without one the builder stays unavailable rather than
/// emitting a structurally valid but cryptographically empty proof.
class DeviceEnvelopeBuilder implements EnvelopeBuilder {
  DeviceEnvelopeBuilder({
    required DeviceKeyMaterial material,
    this.signer,
    this.serverKeyId,
    this.wrappedKey,
    String? installationId,
    this.log,
  })  : _material = material,
        _installationId = installationId ?? material.installationId;

  DeviceKeyMaterial _material;
  final DeviceProofSigner? signer;
  final String? serverKeyId;
  final String? wrappedKey;
  final String? _installationId;
  final void Function(String message)? log;

  DeviceKeyMaterial get material => _material;

  @override
  bool get isReady => signer != null;

  @override
  String get status {
    if (signer == null) {
      return 'device proof signer not bound: supply a DeviceProofSigner backed '
          'by the Keychain key from ${Protocol.channelDeviceKey}';
    }
    if (serverKeyId == null) {
      return 'serverKeyId unknown: fetch ${Protocol.pathTransportKeys} first';
    }
    if (wrappedKey == null) {
      return 'wrappedKey unknown: obtain it from the secure session handshake';
    }
    return 'ready (device=${_material.deviceKeyId}, seq=${_material.sequence})';
  }

  /// Builds the deterministic digest that the device proof covers.
  ///
  /// Canonical form: `schema|deviceKeyId|keyId|sequence|<request json>` with the
  /// request JSON serialised with sorted keys and no whitespace.
  Uint8List sliceChallenge(
    SliceResource r,
    SliceCatalog c,
    int sequence,
  ) {
    final request = <String, dynamic>{
      'path': r.path,
      'remoteSha256': r.remoteSha256,
      'remoteSize': r.remoteSize,
      'resourceId': r.id,
    };
    final canonical = '${Protocol.sliceDeliverySchema}|'
        '${_material.deviceKeyId}|${c.contentKeyId}|$sequence|'
        '${_canonicalJson(request)}';
    return Uint8List.fromList(utf8.encode(canonical));
  }

  static String _canonicalJson(Map<String, dynamic> m) {
    final keys = m.keys.toList()..sort();
    final buf = StringBuffer('{');
    for (var i = 0; i < keys.length; i++) {
      final k = keys[i];
      if (i > 0) buf.write(',');
      buf
        ..write(jsonEncode(k))
        ..write(':')
        ..write(jsonEncode(m[k]));
    }
    buf.write('}');
    return buf.toString();
  }

  @override
  Map<String, dynamic> buildSliceRequest(SliceResource r, SliceCatalog c) {
    final s = signer;
    if (s == null) {
      throw StateError(status);
    }
    final seq = _nextSequence();
    final challenge = sliceChallenge(r, c, seq);
    final proof = s.sign(Protocol.deviceProofSchema, challenge);

    _log('built slice envelope for ${r.path} seq=$seq '
        'proof=${proof.length}B');

    return <String, dynamic>{
      'schema': Protocol.sliceDeliverySchema,
      'deviceKeyId': _material.deviceKeyId,
      'deviceProof': base64Url.encode(proof).replaceAll('=', ''),
      'keyId': c.contentKeyId,
      'sequence': seq,
      'request': <String, dynamic>{
        'resourceId': r.id,
        'path': r.path,
        'cipherSha256': r.cipherSha256,
        'remoteSize': r.remoteSize,
      },
    };
  }

  @override
  Map<String, dynamic> buildSecureListRequest(SliceCatalog c) {
    final s = signer;
    if (s == null) throw StateError(status);
    final seq = _nextSequence();
    final challenge = Uint8List.fromList(utf8.encode(
      '${Protocol.catalogSchema}|${_material.deviceKeyId}|'
      '${c.contentKeyId}|$seq',
    ));
    final proof = s.sign(Protocol.deviceProofSchema, challenge);
    return <String, dynamic>{
      'schema': Protocol.sliceDeliverySchema,
      'deviceKeyId': _material.deviceKeyId,
      'deviceProof': base64Url.encode(proof).replaceAll('=', ''),
      'keyId': c.contentKeyId,
      'sequence': seq,
    };
  }

  @override
  Map<String, dynamic> buildSecureSessionRequest(SliceCatalog c) {
    final s = signer;
    if (s == null) throw StateError(status);
    final seq = _nextSequence();
    final challenge = Uint8List.fromList(utf8.encode(
      'session|${_material.deviceKeyId}|${c.contentKeyId}|$_installationId|$seq',
    ));
    final proof = s.sign(Protocol.deviceProofSchema, challenge);
    return <String, dynamic>{
      'schema': Protocol.sliceDeliverySchema,
      'deviceKeyId': _material.deviceKeyId,
      'deviceProof': base64Url.encode(proof).replaceAll('=', ''),
      'keyId': c.contentKeyId,
      'serverKeyId': serverKeyId,
      'wrappedKey': wrappedKey,
      'installationId': _installationId,
      'sequence': seq,
    };
  }

  int _nextSequence() {
    final next = _material.sequence + 1;
    _material = _material.copyWith(sequence: next);
    return next;
  }

  void _log(String m) => log?.call(m);
}

/// Signs a device-proof challenge with the device key.
///
/// Implementations are platform-bound: on iOS the key lives in the Keychain and
/// signing happens through [Protocol.channelDeviceKey]. Provide a concrete
/// implementation once the key material has been recovered.
abstract class DeviceProofSigner {
  Uint8List sign(String schema, Uint8List challenge);
}

/// Signer that records challenges instead of signing, for dry runs.
class RecordingSigner implements DeviceProofSigner {
  RecordingSigner({this.log});

  final void Function(String message)? log;
  final List<({String schema, Uint8List challenge})> attempts = [];

  @override
  Uint8List sign(String schema, Uint8List challenge) {
    attempts.add((schema: schema, challenge: challenge));
    log?.call('dry-run sign $schema over ${challenge.length}B: '
        '${utf8.decode(challenge, allowMalformed: true)}');
    return Uint8List(64);
  }
}
