import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../core/protocol.dart';
import '../models/slice_catalog.dart';
import 'api_client.dart';

/// Owns the end-to-end reconstruction of built-in slices.
///
/// Pipeline per asset:
///
///   1. read `assets/builtin-slices/<path>.part`  (the locally shipped head)
///   2. request the server tail for the same asset
///   3. `cipher = localHead || remoteTail`, length must equal `cipherSize`
///   4. verify `sha256(cipher) == cipherSha256`
///   5. apply the wrap layer ([SliceCodec]) to obtain the plaintext
///   6. verify `sha256(plain) == sha256`, then write `<path>` to the output dir
///
/// Steps 1-4 are fully determined by data that ships inside the IPA plus one
/// small server response. Step 5 needs the content key delivered through the
/// secure transport envelope; [SliceCodec] therefore takes a [ContentKeySource]
/// so the key can come from a live session, a dumped keychain item, or a
/// caller-supplied constant.
class SliceExtractor {
  SliceExtractor({
    required this.client,
    required this.catalog,
    required this.assetRoot,
    required this.outputDir,
    required this.codec,
    this.log,
    this.verifyCipherHash = true,
    this.verifyPlainHash = true,
  });

  final ApiClient client;
  final SliceCatalog catalog;

  /// Directory that contains `catalog.json` and the `effects/` tree of `.part`
  /// files, i.e. `assets/builtin-slices`.
  final Directory assetRoot;

  /// Destination for reconstructed assets.
  final Directory outputDir;

  final SliceCodec codec;
  final void Function(String message)? log;
  final bool verifyCipherHash;
  final bool verifyPlainHash;

  void _emit(String m) => log?.call(m);

  /// Resolves the on-disk `.part` file for [resource].
  ///
  /// Catalog paths are plain UTF-8, while the shipped files are
  /// percent-encoded on disk (`%E5%B0%8F...`), so both spellings are probed
  /// before falling back to a size-based lookup.
  File? findLocalPart(SliceResource r) {
    final direct = File('${assetRoot.path}${Platform.pathSeparator}'
        '${_native(r.path)}${Protocol.sliceSuffix}');
    if (direct.existsSync() && direct.lengthSync() == r.localSize) {
      return direct;
    }

    final encoded = '${assetRoot.path}${Platform.pathSeparator}'
        '${_percentEncodePath(r.path)}${Protocol.sliceSuffix}';
    final encFile = File(encoded);
    if (encFile.existsSync() && encFile.lengthSync() == r.localSize) {
      return encFile;
    }

    return null;
  }

  static String _native(String p) => p.replaceAll('/', Platform.pathSeparator);

  static String _percentEncodePath(String p) => p
      .split('/')
      .map((seg) => Uri.encodeComponent(seg))
      .join(Platform.pathSeparator);

  /// Reads the local head and checks it against `localSha256`.
  Future<Uint8List> readLocalPart(SliceResource r) async {
    final f = findLocalPart(r);
    if (f == null) {
      throw FileSystemException(
        'local slice missing for ${r.path} (expected ${r.localSize} bytes)',
      );
    }
    final bytes = await f.readAsBytes();
    if (bytes.length != r.localSize) {
      throw FileSystemException(
        'local slice size mismatch for ${r.path}: '
        '${bytes.length} != ${r.localSize}',
      );
    }
    if (verifyCipherHash) {
      final got = sha256.convert(bytes).toString();
      if (got != r.localSha256) {
        throw StateError(
          'localSha256 mismatch for ${r.path}: $got != ${r.localSha256}',
        );
      }
    }
    return bytes;
  }

  /// Fetches the remote tail for [r]. The returned bytes must hash to
  /// `remoteSha256`.
  Future<Uint8List> fetchRemoteTail(SliceResource r) async {
    final bytes = await codec.fetchRemoteTail(r, client);
    if (bytes.length != r.remoteSize) {
      throw StateError(
        'remote tail size mismatch for ${r.path}: '
        '${bytes.length} != ${r.remoteSize}',
      );
    }
    if (verifyCipherHash) {
      final got = sha256.convert(bytes).toString();
      if (got != r.remoteSha256) {
        throw StateError(
          'remoteSha256 mismatch for ${r.path}: $got != ${r.remoteSha256}',
        );
      }
    }
    return bytes;
  }

  /// Stitches head and tail into the full cipher stream and verifies it.
  AssembledAsset assemble(SliceResource r, Uint8List head, Uint8List tail) {
    final b = BytesBuilder(copy: false)
      ..add(head)
      ..add(tail);
    final cipher = b.takeBytes();
    if (cipher.length != r.cipherSize) {
      throw StateError(
        'cipher size mismatch for ${r.path}: '
        '${cipher.length} != ${r.cipherSize}',
      );
    }
    if (verifyCipherHash) {
      final got = sha256.convert(cipher).toString();
      if (got != r.cipherSha256) {
        throw StateError(
          'cipherSha256 mismatch for ${r.path}: $got != ${r.cipherSha256}',
        );
      }
    }
    return AssembledAsset(
      resource: r,
      cipher: cipher,
      localPart: head,
      remoteTail: tail,
    );
  }

  /// Full pipeline for one asset; returns the written file.
  Future<File> extractOne(SliceResource r) async {
    final head = await readLocalPart(r);
    final tail = await fetchRemoteTail(r);
    final assembled = assemble(r, head, tail);
    final plain = await codec.unwrap(assembled, catalog);

    if (plain.length != r.size) {
      throw StateError(
        'plaintext size mismatch for ${r.path}: '
        '${plain.length} != ${r.size}',
      );
    }
    if (verifyPlainHash) {
      final got = sha256.convert(plain).toString();
      if (got != r.sha256) {
        throw StateError(
          'sha256 mismatch for ${r.path}: $got != ${r.sha256}',
        );
      }
    }

    final out = File('${outputDir.path}${Platform.pathSeparator}'
        '${_native(r.path)}');
    await out.parent.create(recursive: true);
    await out.writeAsBytes(plain, flush: true);
    return out;
  }

  /// Runs [extractOne] for every resource, reporting progress.
  Future<ExtractReport> extractAll({
    bool memberOnly = true,
    void Function(int done, int total, SliceResource r)? onProgress,
  }) async {
    final targets = memberOnly ? catalog.memberResources : catalog.resources;
    final report = ExtractReport(startedAt: DateTime.now());
    await outputDir.create(recursive: true);

    var done = 0;
    for (final r in targets) {
      done++;
      onProgress?.call(done, targets.length, r);
      try {
        _emit('[$done/${targets.length}] ${r.path} '
            '(local ${r.localSize} + remote ${r.remoteSize})');
        final f = await extractOne(r);
        report.succeeded.add(f.path);
      } catch (e) {
        _emit('    FAILED ${r.path}: $e');
        report.failed[r.path] = e.toString();
      }
    }

    report.finishedAt = DateTime.now();
    return report;
  }
}

/// Summary of one extraction run.
class ExtractReport {
  ExtractReport({required this.startedAt});

  final DateTime startedAt;
  DateTime? finishedAt;
  final List<String> succeeded = [];
  final Map<String, String> failed = {};

  Duration? get elapsed => finishedAt?.difference(startedAt);

  bool get allOk => failed.isEmpty;

  String summary() {
    final e = elapsed;
    final secs = e == null ? '?' : (e.inMilliseconds / 1000).toStringAsFixed(1);
    return 'succeeded=${succeeded.length} failed=${failed.length} in ${secs}s';
  }
}

/// Supplies the per-content key used by the wrap layer.
abstract class ContentKeySource {
  /// Returns the key identified by [catalog].`contentKeyId`, or null when it is
  /// not available in this environment.
  Future<Uint8List?> contentKeyFor(SliceCatalog catalog);
}

/// Constant key source, used when a key has been recovered out-of-band.
class StaticContentKeySource implements ContentKeySource {
  StaticContentKeySource(this.key);
  final Uint8List key;

  @override
  Future<Uint8List?> contentKeyFor(SliceCatalog catalog) async => key;
}

/// Source backed by a plain hex/base64 string.
class EncodedContentKeySource implements ContentKeySource {
  EncodedContentKeySource(this.encoded);
  final String encoded;

  @override
  Future<Uint8List?> contentKeyFor(SliceCatalog catalog) async {
    final s = encoded.trim();
    if (s.isEmpty) return null;
    try {
      final bytes = base64Url.decode(base64Url.normalize(s)).length == 32
          ? base64Url.decode(base64Url.normalize(s))
          : _hex(s);
      return Uint8List.fromList(bytes);
    } catch (_) {
      try {
        return Uint8List.fromList(_hex(s));
      } catch (_) {
        return null;
      }
    }
  }

  static List<int> _hex(String s) {
    final clean = s.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
    if (clean.length.isOdd) throw const FormatException('odd hex length');
    final out = <int>[];
    for (var i = 0; i < clean.length; i += 2) {
      out.add(int.parse(clean.substring(i, i + 2), radix: 16));
    }
    return out;
  }
}

/// The wrap layer for `.part` cipher streams.
///
/// Two layers sit on top of the raw cipher:
///   * the `MLA1` container header, which prefixes every shipped slice;
///   * the `minglive-slice-wrap-v2` content transform keyed by
///     `catalog.contentKeyId`.
///
/// [fetchRemoteTail] is separated from [unwrap] so a future revision can source
/// bytes from the server, a cached file, or a caller-provided blob without
/// touching the container logic.
abstract class SliceCodec {
  Future<Uint8List> fetchRemoteTail(SliceResource r, ApiClient client);

  Future<Uint8List> unwrap(AssembledAsset asset, SliceCatalog catalog);
}

/// Utility used by codecs: parses the `MLA1` container.
class Mla1Container {
  const Mla1Container({required this.body, required this.hasMagic});

  final Uint8List body;
  final bool hasMagic;

  int get length => body.length;

  /// Strips the 4-byte `MLA1` magic when present.
  static Mla1Container parse(Uint8List raw) {
    final hasMagic = raw.length >= 4 &&
        raw[0] == Protocol.sliceMagic[0] &&
        raw[1] == Protocol.sliceMagic[1] &&
        raw[2] == Protocol.sliceMagic[2] &&
        raw[3] == Protocol.sliceMagic[3];
    if (!hasMagic) return Mla1Container(body: raw, hasMagic: false);
    return Mla1Container(
      body: Uint8List.sublistView(raw, 4),
      hasMagic: true,
    );
  }
}

/// Deterministic pseudo-random stream used to sanity-check a key candidate by
/// attempting an XOR-based recovery. This mirrors the "stream cipher over the
/// stitched cipher" shape of the wrap layer and lets the UI report whether a
/// candidate key produces a structurally valid container (magic / headers)
/// without claiming a full decrypt.
class KeyProbe {
  KeyProbe(this.key);

  final Uint8List key;

  /// Applies a SHA-256 based counter-mode keystream and returns the candidate
  /// plaintext prefix.
  Uint8List probe(Uint8List cipher, {int limit = 64}) {
    final n = min(limit, cipher.length);
    final out = Uint8List(n);
    var counter = 0;
    var off = 0;
    while (off < n) {
      final block = sha256.convert([
        ...key,
        ...(ByteData(4)..setUint32(0, counter, Endian.little)).buffer.asUint8List(),
      ]).bytes;
      for (var i = 0; i < block.length && off < n; i++, off++) {
        out[off] = cipher[off] ^ block[i];
      }
      counter++;
    }
    return out;
  }
}
