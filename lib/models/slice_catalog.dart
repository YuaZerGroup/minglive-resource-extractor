import 'dart:convert';
import 'dart:typed_data';

/// A single entry of `assets/builtin-slices/catalog.json`.
///
/// The catalog describes every built-in asset twice:
///
///   plaintext : [size]         [sha256]
///   cipher    : [cipherSize]   [cipherSha256]
///   local     : [localSize]    [localSha256]   <- bytes shipped inside the IPA
///   remote    : [remoteSize]   [remoteSha256]  <- bytes fetched from the server
///
/// The relationship recovered from all 340 entries is exactly:
///
///   cipherSize == localSize + remoteSize
///
/// i.e. the `.part` file carried by the app *is* the leading portion of the
/// cipher stream and the server supplies the remaining tail. Concatenating the
/// two plain byte ranges reproduces the full cipher, whose SHA-256 must equal
/// [cipherSha256] before it is worth attempting decryption.
class SliceResource {
  const SliceResource({
    required this.id,
    required this.iosAccess,
    required this.path,
    required this.size,
    required this.sha256,
    required this.cipherSize,
    required this.cipherSha256,
    required this.localSize,
    required this.localSha256,
    required this.remoteSize,
    required this.remoteSha256,
  });

  final String id;
  final String iosAccess;
  final String path;
  final int size;
  final String sha256;
  final int cipherSize;
  final String cipherSha256;
  final int localSize;
  final String localSha256;
  final int remoteSize;
  final String remoteSha256;

  bool get isMember => iosAccess == 'MEMBER';

  /// Bytes that live only on the server for this asset.
  int get remoteBytes => remoteSize;

  /// Fraction of the asset that is already present locally.
  double get localRatio => cipherSize == 0 ? 0 : localSize / cipherSize;

  factory SliceResource.fromJson(Map<String, dynamic> j) {
    int asInt(Object? v) {
      if (v is int) return v;
      if (v is num) return v.toInt();
      if (v is String) return int.tryParse(v) ?? 0;
      return 0;
    }

    String asStr(Object? v) => v is String ? v : (v?.toString() ?? '');

    return SliceResource(
      id: asStr(j['id']),
      iosAccess: asStr(j['iosAccess']),
      path: asStr(j['path']),
      size: asInt(j['size']),
      sha256: asStr(j['sha256']),
      cipherSize: asInt(j['cipherSize']),
      cipherSha256: asStr(j['cipherSha256']),
      localSize: asInt(j['localSize']),
      localSha256: asStr(j['localSha256']),
      remoteSize: asInt(j['remoteSize']),
      remoteSha256: asStr(j['remoteSha256']),
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'iosAccess': iosAccess,
        'path': path,
        'size': size,
        'sha256': sha256,
        'cipherSize': cipherSize,
        'cipherSha256': cipherSha256,
        'localSize': localSize,
        'localSha256': localSha256,
        'remoteSize': remoteSize,
        'remoteSha256': remoteSha256,
      };

  @override
  String toString() => 'SliceResource($path, access=$iosAccess, '
      'local=$localSize, remote=$remoteSize, cipher=$cipherSize)';
}

/// The parsed `catalog.json` document.
class SliceCatalog {
  const SliceCatalog({
    required this.schema,
    required this.scope,
    required this.contentKeyId,
    required this.version,
    required this.resources,
    required this.groups,
    required this.duckProbabilities,
    required this.raw,
  });

  final String schema;
  final String scope;
  final String contentKeyId;
  final String version;
  final List<SliceResource> resources;
  final List<Map<String, dynamic>> groups;
  final Map<String, dynamic> duckProbabilities;

  /// Untouched source document, kept so callers can forward it verbatim.
  final Map<String, dynamic> raw;

  List<SliceResource> get memberResources =>
      resources.where((r) => r.isMember).toList(growable: false);

  List<SliceResource> get freeResources =>
      resources.where((r) => !r.isMember).toList(growable: false);

  int get totalRemoteBytes =>
      resources.fold<int>(0, (a, r) => a + r.remoteSize);

  int get memberRemoteBytes =>
      memberResources.fold<int>(0, (a, r) => a + r.remoteSize);

  int get totalCipherBytes =>
      resources.fold<int>(0, (a, r) => a + r.cipherSize);

  factory SliceCatalog.fromJsonString(String source) {
    final doc = jsonDecode(source) as Map<String, dynamic>;
    final list = (doc['resources'] as List<dynamic>? ?? const [])
        .whereType<Map<String, dynamic>>()
        .map(SliceResource.fromJson)
        .toList(growable: false);

    final groups = (doc['groups'] as List<dynamic>? ?? const [])
        .whereType<Map<String, dynamic>>()
        .toList(growable: false);

    final duck = doc['duckProbabilities'];
    return SliceCatalog(
      schema: doc['schema'] as String? ?? '',
      scope: doc['scope'] as String? ?? '',
      contentKeyId: doc['contentKeyId'] as String? ?? '',
      version: doc['version'] as String? ?? '',
      resources: list,
      groups: groups,
      duckProbabilities:
          duck is Map<String, dynamic> ? duck : <String, dynamic>{},
      raw: doc,
    );
  }
}

/// Result of stitching the local `.part` slice with the server tail.
class AssembledAsset {
  const AssembledAsset({
    required this.resource,
    required this.cipher,
    required this.localPart,
    required this.remoteTail,
  });

  final SliceResource resource;

  /// `localPart + remoteTail`, exactly [SliceResource.cipherSize] bytes.
  final Uint8List cipher;
  final Uint8List localPart;
  final Uint8List remoteTail;

  int get cipherLength => cipher.length;
  int get localLength => localPart.length;
  int get remoteLength => remoteTail.length;
}
