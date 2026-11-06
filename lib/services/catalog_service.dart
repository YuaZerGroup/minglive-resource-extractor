import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart' show rootBundle;

import '../core/protocol.dart';
import '../models/slice_catalog.dart';

/// Locates and inventories the built-in slice assets shipped in this app.
///
/// Two packaging modes are supported:
///
///  * **bundled** – `assets/builtin-slices/**` declared in `pubspec.yaml` and
///    read through the asset bundle (used on iOS, where the payload lives inside
///    the `.app`).
///  * **unpacked** – a real directory on disk (used by desktop/tooling runs,
///    where reading 340 files through the bundle is slower than direct IO).
class CatalogService {
  CatalogService({
    this.assetDirectory,
    this.log,
  });

  /// When non-null, `.part` files are read from this directory instead of the
  /// Flutter asset bundle.
  final Directory? assetDirectory;

  final void Function(String message)? log;

  void _emit(String m) => log?.call(m);

  /// Loads `catalog.json` from whichever source is configured.
  Future<SliceCatalog> loadCatalog() async {
    late String source;
    if (assetDirectory != null) {
      final f = File(
        '${assetDirectory!.path}${Platform.pathSeparator}catalog.json',
      );
      if (!f.existsSync()) {
        throw FileSystemException('catalog.json not found', f.path);
      }
      source = await f.readAsString();
    } else {
      source = await rootBundle.loadString(Protocol.catalogAssetPath);
    }

    final catalog = SliceCatalog.fromJsonString(source);
    _emit('catalog loaded: ${catalog.resources.length} resources, '
        '${catalog.memberResources.length} MEMBER, '
        'schema=${catalog.schema}');
    _emit('contentKeyId=${catalog.contentKeyId}');
    _emit('version=${catalog.version}');
    _emit('remote bytes required: ${catalog.totalRemoteBytes} total, '
        '${catalog.memberRemoteBytes} for MEMBER assets');
    return catalog;
  }

  /// Reads one `.part` slice, preferring the direct path then the
  /// percent-encoded spelling used on disk.
  Future<Uint8List?> readSlice(SliceResource r) async {
    final candidates = _candidateNames(r.path);
    if (assetDirectory != null) {
      for (final name in candidates) {
        final f = File('${assetDirectory!.path}${Platform.pathSeparator}$name'
            '${Protocol.sliceSuffix}');
        if (f.existsSync()) return f.readAsBytes();
      }
      return null;
    }
    for (final name in candidates) {
      final key =
          '${Protocol.catalogAssetDir}${name.replaceAll(Platform.pathSeparator, '/')}'
          '${Protocol.sliceSuffix}';
      try {
        final data = await rootBundle.load(key);
        return data.buffer.asUint8List(
          data.offsetInBytes,
          data.lengthInBytes,
        );
      } catch (_) {
        continue;
      }
    }
    return null;
  }

  /// Candidate on-disk spellings for a catalog path.
  ///
  /// The shipped catalog uses plain UTF-8 paths (`effects/audio/铃声.mp3`). The
  /// files are packaged under exactly those names so a single lookup normally
  /// suffices; the percent-encoded variant is kept as a fallback because some
  /// packaging tools rewrite non-ASCII names to `%E5%B0%8F` form.
  List<String> _candidateNames(String catalogPath) {
    final native = catalogPath.replaceAll('/', Platform.pathSeparator);
    final encoded = catalogPath
        .split('/')
        .map(Uri.encodeComponent)
        .join(Platform.pathSeparator);
    return native == encoded ? [native] : [native, encoded];
  }

  /// Verifies every local slice against `localSha256`.
  ///
  /// Progress callbacks fire once per resource so the UI can render a live bar.
  Future<LocalInventory> inventory(
    SliceCatalog catalog, {
    bool memberOnly = false,
    void Function(int done, int total, SliceResource r)? onProgress,
  }) async {
    final targets =
        memberOnly ? catalog.memberResources : catalog.resources;
    final inv = LocalInventory();
    var done = 0;

    for (final r in targets) {
      done++;
      onProgress?.call(done, targets.length, r);
      final bytes = await readSlice(r);
      if (bytes == null) {
        inv.missing.add(r.path);
        continue;
      }
      if (bytes.length != r.localSize) {
        inv.sizeMismatch[r.path] = '${bytes.length} != ${r.localSize}';
        continue;
      }
      final digest = sha256.convert(bytes).toString();
      if (digest != r.localSha256) {
        inv.hashMismatch[r.path] = digest;
        continue;
      }
      inv.verified++;
      inv.verifiedBytes += bytes.length;
    }

    _emit('inventory: verified=${inv.verified}/${targets.length} '
        '(${(inv.verifiedBytes / (1024 * 1024)).toStringAsFixed(1)} MiB), '
        'missing=${inv.missing.length}, '
        'sizeMismatch=${inv.sizeMismatch.length}, '
        'hashMismatch=${inv.hashMismatch.length}');
    return inv;
  }

  /// Builds a human readable plan of what the server still has to supply.
  String describeRemotePlan(SliceCatalog catalog, {bool memberOnly = true}) {
    final targets =
        memberOnly ? catalog.memberResources : catalog.resources;
    final buf = StringBuffer();
    final totalRemote = targets.fold<int>(0, (a, r) => a + r.remoteSize);
    final totalCipher = targets.fold<int>(0, (a, r) => a + r.cipherSize);
    final totalPlain = targets.fold<int>(0, (a, r) => a + r.size);

    buf.writeln('assets: ${targets.length}');
    buf.writeln('plaintext total: $totalPlain bytes');
    buf.writeln('cipher total: $totalCipher bytes');
    buf.writeln('local head total: ${totalCipher - totalRemote} bytes '
        '(${((totalCipher - totalRemote) / totalCipher * 100).toStringAsFixed(2)}%)');
    buf.writeln('remote tail total: $totalRemote bytes '
        '(${(totalRemote / totalCipher * 100).toStringAsFixed(2)}%)');
    if (targets.isNotEmpty) {
      buf.writeln('example: ${targets.first.path} '
          'local=${targets.first.localSize} + remote=${targets.first.remoteSize}'
          ' = cipher=${targets.first.cipherSize}');
    }
    return buf.toString();
  }
}

/// Aggregate result of a local verification pass.
class LocalInventory {
  int verified = 0;
  int verifiedBytes = 0;
  final List<String> missing = [];
  final Map<String, String> sizeMismatch = {};
  final Map<String, String> hashMismatch = {};

  bool get isClean =>
      missing.isEmpty && sizeMismatch.isEmpty && hashMismatch.isEmpty;

  String summary() =>
      'verified=$verified missing=${missing.length} '
      'sizeMismatch=${sizeMismatch.length} hashMismatch=${hashMismatch.length}';
}

/// Loads the catalog straight from a JSON string, used by tests and tooling.
Future<SliceCatalog> loadCatalogFromJson(String src) async =>
    SliceCatalog.fromJsonString(src);
