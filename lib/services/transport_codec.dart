import 'dart:convert';
import 'dart:typed_data';

import '../core/protocol.dart';
import '../models/slice_catalog.dart';
import 'api_client.dart';
import 'slice_extractor.dart';

/// Remote-tail transport used by [TransportCodec].
///
/// Two strategies are supported because the origin exposes the same asset data
/// through more than one door:
///
///  * [RemoteSource.secureFeature] – `POST /features/secure-builtin-slices-<s>`
///    with a signed envelope. This is the route the shipped app uses and the
///    only one that returns the wrap-layer key material.
///  * [RemoteSource.staticAsset] – a plain path request on the same origin.
///    Useful to confirm reachability and byte-for-byte tail identity without a
///    device proof.
enum RemoteSource { secureFeature, staticAsset }

/// Configuration for how the tail of each cipher stream is obtained.
class TransportCodecConfig {
  const TransportCodecConfig({
    this.source = RemoteSource.secureFeature,
    this.suffix,
    this.staticPathTemplate,
    this.envelopeBuilder,
    this.responseDecoder,
  });

  final RemoteSource source;

  /// Identifier appended to [Protocol.pathSlicesPrefix]; defaults to the
  /// catalog version.
  final String? suffix;

  /// Template for [RemoteSource.staticAsset]; `{path}`, `{id}`, `{sha}`
  /// placeholders are substituted.
  final String? staticPathTemplate;

  /// Builds the secure request body. Required for [RemoteSource.secureFeature].
  final Map<String, dynamic> Function(SliceResource r, SliceCatalog c)?
      envelopeBuilder;

  /// Extracts raw tail bytes from a secure response document.
  final Uint8List Function(Map<String, dynamic> body)? responseDecoder;
}

/// Default codec: real HTTP transport, container parsing, honest failure when
/// the wrap key is unavailable.
///
/// `MLA1` is the only header observed on disk (4 bytes), and everything after
/// it is high-entropy. That means the wrap layer carries no self-describing
/// metadata, so a key is required before the bytes can become plaintext. This
/// class therefore performs every step that *is* fully determined by shipped
/// data (container split, length math, both SHA-256 checks) and reports an
/// explicit [WrapKeyUnavailable] instead of fabricating a plaintext.
class TransportCodec implements SliceCodec {
  TransportCodec({
    required this.config,
    required this.keySource,
    this.log,
  });

  final TransportCodecConfig config;
  final ContentKeySource keySource;
  final void Function(String message)? log;

  void _emit(String m) => log?.call(m);

  @override
  Future<Uint8List> fetchRemoteTail(SliceResource r, ApiClient client) async {
    switch (config.source) {
      case RemoteSource.staticAsset:
        final tmpl = config.staticPathTemplate ?? '/builtin-slices/{path}';
        final path = tmpl
            .replaceAll('{path}', Uri.encodeComponent(r.path))
            .replaceAll('{id}', r.id)
            .replaceAll('{sha}', r.remoteSha256);
        final res = await client.getJson(path);
        if (!res.isOk) throw ApiException(res);
        return _rawBytes(res);

      case RemoteSource.secureFeature:
        final builder = config.envelopeBuilder;
        if (builder == null) {
          throw StateError(
            'TransportCodec: secureFeature needs envelopeBuilder '
            '(device proof signing is not available in this build)',
          );
        }
        final catalog = _lastCatalog;
        if (catalog == null) {
          throw StateError(
            'TransportCodec.bindCatalog must be called before fetching tails',
          );
        }
        final suffix = config.suffix ?? catalog.version;
        final path = '${Protocol.pathSlicesPrefix}$suffix';
        final body = builder(r, catalog);
        final res = await client.postJson(path, body, auth: true);
        if (!res.isOk) throw ApiException(res);
        final decoded = config.responseDecoder;
        if (decoded == null || res.json == null) {
          throw StateError('secure slice response is not a JSON envelope');
        }
        return decoded(res.json!);
    }
  }

  SliceCatalog? _lastCatalog;

  /// Codec needs the catalog to build envelopes; the extractor supplies it via
  /// [unwrap] before any tail fetch happens, and [bindCatalog] makes that
  /// explicit for callers that fetch tails eagerly.
  void bindCatalog(SliceCatalog c) => _lastCatalog = c;

  Uint8List _rawBytes(ApiResponse res) {
    // Static responses are either a base64 document or raw bytes delivered as
    // a JSON string field.
    final j = res.json;
    if (j != null) {
      for (final k in const ['data', 'ciphertext', 'payload', 'content', 'body']) {
        final v = j[k];
        if (v is String && v.isNotEmpty) return _decodeMaybeBase64(v);
      }
    }
    return Uint8List.fromList(utf8.encode(res.body));
  }

  static Uint8List _decodeMaybeBase64(String s) {
    try {
      return Uint8List.fromList(base64Url.decode(base64Url.normalize(s)));
    } catch (_) {
      try {
        return Uint8List.fromList(base64.decode(s));
      } catch (_) {
        return Uint8List.fromList(utf8.encode(s));
      }
    }
  }

  @override
  Future<Uint8List> unwrap(AssembledAsset asset, SliceCatalog catalog) async {
    bindCatalog(catalog);

    final container = Mla1Container.parse(asset.cipher);
    _emit('  container: magic=${container.hasMagic} '
        'body=${container.body.length}/${asset.resource.cipherSize}');

    final key = await keySource.contentKeyFor(catalog);
    if (key == null) {
      throw WrapKeyUnavailable(
        'no content key for contentKeyId=${catalog.contentKeyId.textOrEmpty} '
        'path=${asset.resource.path} '
        '(cipher assembled and verified: ${asset.cipherLength} bytes, '
        'local ${asset.localLength} + remote ${asset.remoteLength})',
      );
    }

    return applyWrap(container.body, key, asset.resource);
  }

  /// The wrap layer. Implemented as an explicit hook so a recovered algorithm
  /// can be dropped in without touching the transport or verification code.
  Uint8List applyWrap(Uint8List body, Uint8List key, SliceResource r) {
    throw WrapAlgorithmUnknown(
      'key present (${key.length} bytes) but the '
      '${Protocol.sliceWrapSchema} transform is not reproduced in this build; '
      'asset=${r.path}',
    );
  }
}

extension on String {
  String get textOrEmpty => this;
}

/// Raised when the wrap key could not be obtained for the current session.
class WrapKeyUnavailable implements Exception {
  WrapKeyUnavailable(this.message);
  final String message;
  @override
  String toString() => 'WrapKeyUnavailable: $message';
}

/// Raised when the key exists but the transform is not implemented.
class WrapAlgorithmUnknown implements Exception {
  WrapAlgorithmUnknown(this.message);
  final String message;
  @override
  String toString() => 'WrapAlgorithmUnknown: $message';
}

/// Codec that only performs the local half of the pipeline and writes the
/// verified cipher stream instead of a decrypted asset.
///
/// This is the mode to use before a wrap key is available: it proves the local
/// 99% is intact, records exactly which bytes are missing, and produces a
/// reproducible artifact for later decryption.
class CipherOnlyCodec implements SliceCodec {
  CipherOnlyCodec({required this.config, this.log});

  final TransportCodecConfig config;
  final void Function(String message)? log;

  @override
  Future<Uint8List> fetchRemoteTail(SliceResource r, ApiClient client) async {
    final codec = TransportCodec(
      config: config,
      keySource: _NoKey(),
      log: log,
    );
    return codec.fetchRemoteTail(r, client);
  }

  @override
  Future<Uint8List> unwrap(AssembledAsset asset, SliceCatalog catalog) async {
    // Return the assembled cipher verbatim. The extractor's plaintext checks
    // are disabled by the caller in this mode.
    return asset.cipher;
  }
}

class _NoKey implements ContentKeySource {
  @override
  Future<Uint8List?> contentKeyFor(SliceCatalog catalog) async => null;
}
