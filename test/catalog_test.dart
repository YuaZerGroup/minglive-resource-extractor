import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:minglive_resource_extractor/core/protocol.dart';
import 'package:minglive_resource_extractor/models/slice_catalog.dart';
import 'package:minglive_resource_extractor/services/api_client.dart';
import 'package:minglive_resource_extractor/services/slice_extractor.dart';

/// These tests run against the real catalog and the real `.part` slices that
/// ship inside the app, so they double as an integrity check of the packaged
/// assets. They do not touch the network: the remote tail is supplied by a
/// stub codec, which is enough to prove the stitching and verification logic.
void main() {
  const assetRoot = 'assets/builtin-slices';
  final catalogFile = File('$assetRoot/catalog.json');

  late SliceCatalog catalog;

  setUpAll(() {
    expect(catalogFile.existsSync(), isTrue,
        reason: 'catalog.json must ship with the app');
    catalog = SliceCatalog.fromJsonString(catalogFile.readAsStringSync());
  });

  /// A real [ApiClient] pointing at an unroutable host. No test in this file
  /// issues a request, so it is never contacted; using the concrete type keeps
  /// the extractor's signature honest.
  ApiClient offlineClient() => ApiClient(
        baseUrl: 'http://127.0.0.1:1',
        trustAnyCertificate: true,
      );

  group('catalog', () {
    test('has the expected shape', () {
      expect(catalog.schema, Protocol.catalogSchema);
      expect(catalog.resources, isNotEmpty);
      expect(catalog.contentKeyId, hasLength(64));
      expect(catalog.version, hasLength(64));
    });

    test('splits MEMBER and FREE resources', () {
      final member = catalog.memberResources;
      final free = catalog.freeResources;
      expect(member.length + free.length, catalog.resources.length);
      expect(member, isNotEmpty, reason: 'member assets must exist');
      for (final r in member) {
        expect(r.iosAccess, Protocol.tierMember);
      }
      for (final r in free) {
        expect(r.iosAccess, Protocol.tierFree);
      }
    });

    test('every entry satisfies cipherSize == localSize + remoteSize', () {
      for (final r in catalog.resources) {
        expect(
          r.cipherSize,
          r.localSize + r.remoteSize,
          reason: 'size identity broken for ${r.path}',
        );
      }
    });

    test('remote share is about one percent of the cipher stream', () {
      final total = catalog.totalCipherBytes;
      final remote = catalog.totalRemoteBytes;
      expect(total, greaterThan(0));
      final pct = remote / total * 100;
      // Observed on the shipped catalog: ~1.0%.
      expect(pct, lessThan(5.0),
          reason: 'remote share should stay near 1%, got ${pct.toStringAsFixed(3)}%');
    });

    test('every entry carries both digests', () {
      for (final r in catalog.resources) {
        expect(r.sha256, hasLength(64));
        expect(r.cipherSha256, hasLength(64));
        expect(r.localSha256, hasLength(64));
        expect(r.remoteSha256, hasLength(64));
      }
    });
  });

  group('local slices', () {
    test('all MEMBER slices exist and match localSha256', () async {
      final extractor = SliceExtractor(
        client: offlineClient(),
        catalog: catalog,
        assetRoot: Directory(assetRoot),
        outputDir: Directory.systemTemp.createTempSync('mlslices'),
        codec: _StubCodec(),
      );

      var checked = 0;
      for (final r in catalog.memberResources) {
        final head = await extractor.readLocalPart(r);
        expect(head.length, r.localSize, reason: r.path);
        expect(sha256.convert(head).toString(), r.localSha256,
            reason: 'localSha256 mismatch for ${r.path}');
        checked++;
      }
      expect(checked, catalog.memberResources.length);
      expect(checked, greaterThan(0));
    });
  });

  group('stitching', () {
    test('head + tail reproduces cipherSize and cipher hash', () async {
      // Build a synthetic asset with a deterministic tail so the stitcher can be
      // exercised without a server.
      const headBytes = [1, 2, 3, 4, 5, 6, 7, 8];
      const tailBytes = [9, 10, 11, 12];
      final cipher = Uint8List.fromList([...headBytes, ...tailBytes]);

      final synthetic = SliceResource(
        id: 'synthetic',
        iosAccess: Protocol.tierMember,
        path: 'effects/audio/synthetic.mp3',
        size: cipher.length,
        sha256: sha256.convert(cipher).toString(),
        cipherSize: cipher.length,
        cipherSha256: sha256.convert(cipher).toString(),
        localSize: headBytes.length,
        localSha256: sha256.convert(headBytes).toString(),
        remoteSize: tailBytes.length,
        remoteSha256: sha256.convert(tailBytes).toString(),
      );

      final extractor = SliceExtractor(
        client: offlineClient(),
        catalog: catalog,
        assetRoot: Directory(assetRoot),
        outputDir: Directory.systemTemp.createTempSync('mlslices'),
        codec: _StubCodec(),
      );

      final assembled = extractor.assemble(
        synthetic,
        Uint8List.fromList(headBytes),
        Uint8List.fromList(tailBytes),
      );

      expect(assembled.cipherLength, synthetic.cipherSize);
      expect(assembled.localLength, synthetic.localSize);
      expect(assembled.remoteLength, synthetic.remoteSize);
      expect(byteList(assembled.cipher), byteList(cipher));
    });

    test('rejects a cipher that does not match cipherSha256', () {
      const headBytes = [1, 2, 3, 4];
      final cipher = Uint8List.fromList([...headBytes, 9, 9, 9]);

      // `assemble` validates the stitched stream against `cipherSha256`. The
      // per-half `localSha256` / `remoteSha256` checks belong to
      // `readLocalPart` / `fetchRemoteTail`, which are covered separately.
      final synthetic = SliceResource(
        id: 'bad',
        iosAccess: Protocol.tierMember,
        path: 'x',
        size: cipher.length,
        sha256: sha256.convert(cipher).toString(),
        cipherSize: cipher.length,
        cipherSha256: '0' * 64, // deliberately wrong
        localSize: headBytes.length,
        localSha256: sha256.convert(headBytes).toString(),
        remoteSize: 3,
        remoteSha256: sha256.convert([9, 9, 9]).toString(),
      );

      final extractor = SliceExtractor(
        client: offlineClient(),
        catalog: catalog,
        assetRoot: Directory(assetRoot),
        outputDir: Directory.systemTemp.createTempSync('mlslices'),
        codec: _StubCodec(),
      );

      expect(
        () => extractor.assemble(
          synthetic,
          Uint8List.fromList(headBytes),
          Uint8List.fromList([9, 9, 9]),
        ),
        throwsA(isA<StateError>()),
      );
    });

    test('accepts a correctly hashed stitch', () {
      const headBytes = [1, 2, 3, 4];
      const tailBytes = [9, 9, 9];
      final cipher = Uint8List.fromList([...headBytes, ...tailBytes]);

      final synthetic = SliceResource(
        id: 'good',
        iosAccess: Protocol.tierMember,
        path: 'z',
        size: cipher.length,
        sha256: sha256.convert(cipher).toString(),
        cipherSize: cipher.length,
        cipherSha256: sha256.convert(cipher).toString(),
        localSize: headBytes.length,
        localSha256: sha256.convert(headBytes).toString(),
        remoteSize: tailBytes.length,
        remoteSha256: sha256.convert(tailBytes).toString(),
      );

      final extractor = SliceExtractor(
        client: offlineClient(),
        catalog: catalog,
        assetRoot: Directory(assetRoot),
        outputDir: Directory.systemTemp.createTempSync('mlslices'),
        codec: _StubCodec(),
      );

      final a = extractor.assemble(
        synthetic,
        Uint8List.fromList(headBytes),
        Uint8List.fromList(tailBytes),
      );
      expect(a.cipherLength, cipher.length);
      expect(byteList(a.cipher), byteList(cipher));
    });

    test('rejects a cipher whose length is off', () {
      const headBytes = [1, 2, 3];
      final synthetic = SliceResource(
        id: 'short',
        iosAccess: Protocol.tierMember,
        path: 'y',
        size: 10,
        sha256: '0' * 64,
        cipherSize: 10,
        cipherSha256: '0' * 64,
        localSize: headBytes.length,
        localSha256: '0' * 64,
        remoteSize: 3,
        remoteSha256: '0' * 64,
      );
      final extractor = SliceExtractor(
        client: offlineClient(),
        catalog: catalog,
        assetRoot: Directory(assetRoot),
        outputDir: Directory.systemTemp.createTempSync('mlslices'),
        codec: _StubCodec(),
        verifyCipherHash: false,
      );
      expect(
        () => extractor.assemble(
          synthetic,
          Uint8List.fromList(headBytes),
          Uint8List.fromList([4, 5, 6]),
        ),
        throwsA(isA<StateError>()),
      );
    });
  });

  group('MLA1 container', () {
    test('strips the magic when present', () {
      final raw = Uint8List.fromList([0x4D, 0x4C, 0x41, 0x31, 1, 2, 3]);
      final c = Mla1Container.parse(raw);
      expect(c.hasMagic, isTrue);
      expect(c.body, equals([1, 2, 3]));
    });

    test('passes through when absent', () {
      final raw = Uint8List.fromList([1, 2, 3]);
      final c = Mla1Container.parse(raw);
      expect(c.hasMagic, isFalse);
      expect(c.body.length, 3);
    });
  });

  group('content key source', () {
    test('decodes hex', () async {
      final src = EncodedContentKeySource('00' * 32);
      final key = await src.contentKeyFor(catalog);
      expect(key, isNotNull);
      expect(key!.length, 32);
    });

    test('decodes base64url', () async {
      final raw = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final src = EncodedContentKeySource(base64Url.encode(raw));
      final key = await src.contentKeyFor(catalog);
      expect(key, isNotNull);
      expect(byteList(key!), byteList(raw));
    });

    test('returns null for empty input', () async {
      expect(await EncodedContentKeySource('').contentKeyFor(catalog), isNull);
    });
  });
}

List<int> byteList(List<int> v) => v.toList(growable: false);

/// Supplies a zeroed tail so stitching can be exercised deterministically.
class _StubCodec implements SliceCodec {
  @override
  Future<Uint8List> fetchRemoteTail(SliceResource r, ApiClient client) async =>
      Uint8List(r.remoteSize);

  @override
  Future<Uint8List> unwrap(AssembledAsset asset, SliceCatalog catalog) async =>
      asset.cipher;
}
