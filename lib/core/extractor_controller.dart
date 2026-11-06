import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../core/protocol.dart';
import '../models/slice_catalog.dart';
import '../services/api_client.dart';
import '../services/auth_service.dart';
import '../services/catalog_service.dart';
import '../services/envelope.dart';
import '../services/slice_extractor.dart';
import '../services/transport_codec.dart';
import '../services/transport_key_service.dart';

/// Which part of the pipeline is currently running.
enum PipelineStage {
  idle,
  loadingCatalog,
  inventory,
  loggingIn,
  fetchingKeys,
  buildingEnvelope,
  extracting,
  done,
  failed,
}

/// Orchestrates the whole reconstruction for the UI.
class ExtractorController extends ChangeNotifier {
  ExtractorController();

  // ------------------------------------------------------------------ config
  String baseUrl = Protocol.defaultBaseUrl;
  String userAgent = Protocol.userAgent;
  bool trustAnyCertificate = true;

  // ------------------------------------------------------------------- state
  PipelineStage stage = PipelineStage.idle;
  final List<String> logs = [];
  SliceCatalog? catalog;
  LocalInventory? inventory;
  Session? session;
  TransportKeyManifest? transportKeys;

  int progressDone = 0;
  int progressTotal = 0;
  String? currentPath;
  ExtractReport? report;
  String? error;

  ApiClient? _client;
  bool _busy = false;

  bool get busy => _busy;
  bool get hasCatalog => catalog != null;
  bool get isMember => session?.user.membership.grantsMemberAccess ?? false;

  double get progress =>
      progressTotal == 0 ? 0 : progressDone / progressTotal;

  /// Everything the UI needs to explain what the current build can and cannot
  /// do, so the user is never left guessing why a step stopped.
  String get capabilitySummary {
    final buf = StringBuffer();
    buf.writeln('baseUrl: $baseUrl');
    if (catalog != null) {
      buf.writeln('catalog: ${catalog!.resources.length} resources '
          '(${catalog!.memberResources.length} MEMBER)');
      buf.writeln('remote bytes needed: ${catalog!.memberRemoteBytes} '
          'for MEMBER assets');
    }
    if (transportKeys != null) {
      buf.writeln('transport key: ${transportKeys!.activeKeyId}');
    }
    if (session != null) {
      buf.writeln('user: ${session!.user.username} '
          '(${session!.user.membership.tier})');
    }
    return buf.toString();
  }

  void log(String message) {
    final line = '[${_ts()}] $message';
    logs.add(line);
    if (logs.length > 2000) logs.removeRange(0, logs.length - 2000);
    notifyListeners();
  }

  static String _ts() {
    final n = DateTime.now();
    String two(int v) => v.toString().padLeft(2, '0');
    return '${two(n.hour)}:${two(n.minute)}:${two(n.second)}';
  }

  void reset() {
    stage = PipelineStage.idle;
    logs.clear();
    catalog = null;
    inventory = null;
    session = null;
    transportKeys = null;
    report = null;
    error = null;
    progressDone = 0;
    progressTotal = 0;
    currentPath = null;
    _client?.close();
    _client = null;
    notifyListeners();
  }

  ApiClient _ensureClient() {
    final c = _client;
    if (c != null) return c;
    final fresh = ApiClient(
      baseUrl: baseUrl,
      userAgent: userAgent,
      trustAnyCertificate: trustAnyCertificate,
      log: log,
    );
    _client = fresh;
    return fresh;
  }

  /// Step 1: load `catalog.json` and verify all local slices.
  Future<void> loadCatalogAndVerify({bool memberOnly = false}) async {
    await _guard(() async {
      stage = PipelineStage.loadingCatalog;
      notifyListeners();

      final svc = CatalogService(log: log);
      catalog = await svc.loadCatalog();
      final cat = catalog!;
      log(svc.describeRemotePlan(cat, memberOnly: memberOnly));

      stage = PipelineStage.inventory;
      progressDone = 0;
      progressTotal = memberOnly
          ? cat.memberResources.length
          : cat.resources.length;
      notifyListeners();

      inventory = await svc.inventory(
        cat,
        memberOnly: memberOnly,
        onProgress: (done, total, r) {
          progressDone = done;
          progressTotal = total;
          currentPath = r.path;
          if (done == total || done % 25 == 0) notifyListeners();
        },
      );

      final inv = inventory!;
      log('local inventory: ${inv.summary()}');
      if (!inv.isClean) {
        if (inv.missing.isNotEmpty) {
          log('missing slices: ${inv.missing.take(5).join(', ')}'
              '${inv.missing.length > 5 ? ' ...' : ''}');
        }
        if (inv.sizeMismatch.isNotEmpty) {
          log('size mismatches: ${inv.sizeMismatch.entries.take(5).map(
                (e) => '${e.key} (${e.value})',
              ).join(', ')}');
        }
        if (inv.hashMismatch.isNotEmpty) {
          log('hash mismatches: ${inv.hashMismatch.keys.take(5).join(', ')}');
        }
      }
      stage = PipelineStage.idle;
    });
  }

  /// Step 2: log in and capture the membership snapshot.
  Future<void> login(String usernameOrEmail, String password) async {
    await _guard(() async {
      stage = PipelineStage.loggingIn;
      notifyListeners();

      final client = _ensureClient();
      final auth = AuthService(client: client, log: log);
      session = await auth.login(
        usernameOrEmail: usernameOrEmail,
        password: password,
      );

      final m = session!.user.membership;
      if (m.isMember) {
        log('membership: ${m.tier} until ${m.expiresAt} '
            '-> MEMBER assets unlocked');
      } else {
        log('membership: ${m.tier.isEmpty ? 'none' : m.tier} '
            '-> only FREE assets available');
      }
      stage = PipelineStage.idle;
    });
  }

  /// Step 3: fetch the (unauthenticated) transport key manifest.
  Future<void> fetchTransportKeys() async {
    await _guard(() async {
      stage = PipelineStage.fetchingKeys;
      notifyListeners();

      final client = _ensureClient();
      final svc = TransportKeyService(client: client, log: log);
      transportKeys = await svc.fetch();
      svc.checkStructure(transportKeys!);
      stage = PipelineStage.idle;
    });
  }

  /// Step 4: probe the secure endpoints and record what the server answers.
  ///
  /// This deliberately sends the envelope shape recovered from the binary so
  /// the log shows the exact failure the server returns. It never claims success
  /// it did not observe.
  Future<void> probeSecureEndpoints() async {
    await _guard(() async {
      final cat = catalog;
      if (cat == null) throw StateError('load the catalog first');
      final client = _ensureClient();
      if (session == null) throw StateError('log in first');

      stage = PipelineStage.buildingEnvelope;
      notifyListeners();

      const builder = UnavailableEnvelopeBuilder(
        'device proof unavailable: the Keychain-backed key from '
        '${Protocol.channelDeviceKey} is not present in this build',
      );

      for (final path in const [
        Protocol.pathSecureList,
        Protocol.pathSecureSession,
        '${Protocol.pathSlicesPrefix}${'<suffix>'}',
      ]) {
        log('POST $path (probe)');
        try {
          final res = await client.postJson(
            path,
            <String, dynamic>{
              'deviceProof': '',
              'deviceKeyId': '',
              'keyId': cat.contentKeyId,
              'sequence': 1,
            },
            auth: true,
          );
          log('  -> HTTP ${res.statusCode} '
              '${res.serverMessage ?? res.body.substring(0, res.body.length.clamp(0, 200))}');
        } catch (e) {
          log('  -> $e');
        }
      }
      log('probe finished; builder status: ${builder.status}');
      stage = PipelineStage.idle;
    });
  }

  /// Step 5: run the full extraction pipeline.
  ///
  /// [cipherOnly] writes the assembled cipher stream instead of a decrypted
  /// asset, which is the correct mode until the wrap key is recoverable. The
  /// run still proves the local 99% is byte-exact and records precisely which
  /// remote bytes are required.
  Future<void> runExtraction({
    required Directory outputDir,
    bool memberOnly = true,
    bool cipherOnly = true,
  }) async {
    await _guard(() async {
      final cat = catalog;
      if (cat == null) throw StateError('load the catalog first');
      final client = _ensureClient();

      stage = PipelineStage.extracting;
      progressDone = 0;
      progressTotal =
          (memberOnly ? cat.memberResources : cat.resources).length;
      notifyListeners();

      const envelopeBuilder = UnavailableEnvelopeBuilder(
        'device proof unavailable: ${Protocol.channelDeviceKey} key not bound',
      );
      final config = TransportCodecConfig(
        source: RemoteSource.staticAsset,
        envelopeBuilder: envelopeBuilder.isReady
            ? envelopeBuilder.buildSliceRequest
            : null,
      );

      final codec = cipherOnly
          ? CipherOnlyCodec(config: config, log: log)
          : TransportCodec(
              config: config,
              keySource: EncodedContentKeySource(''),
              log: log,
            );

      final assetRoot = Directory('assets/builtin-slices');
      final extractor = SliceExtractor(
        client: client,
        catalog: cat,
        assetRoot: assetRoot,
        outputDir: outputDir,
        codec: codec,
        log: log,
        verifyPlainHash: !cipherOnly,
      );

      report = await extractor.extractAll(
        memberOnly: memberOnly,
        onProgress: (done, total, r) {
          progressDone = done;
          progressTotal = total;
          currentPath = r.path;
          notifyListeners();
        },
      );

      log('extraction finished: ${report!.summary()}');
      if (!report!.allOk) {
        log('failures: ${report!.failed.length}. '
            'First: ${report!.failed.entries.first}');
      }
      stage = PipelineStage.done;
    });
  }

  Future<void> _guard(Future<void> Function() body) async {
    if (_busy) return;
    _busy = true;
    error = null;
    notifyListeners();
    try {
      await body();
    } catch (e, st) {
      stage = PipelineStage.failed;
      error = e.toString();
      log('ERROR: $e');
      if (kDebugMode) log('$st');
    } finally {
      _busy = false;
      notifyListeners();
    }
  }

  @override
  void dispose() {
    _client?.close();
    super.dispose();
  }
}
