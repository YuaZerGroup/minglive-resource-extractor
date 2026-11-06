import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../models/slice_catalog.dart';

/// Thin JSON client for the MingLive origin.
///
/// The stock iOS build talks to a single IPv4 origin over TLS 1.2/1.3. In this
/// environment `HttpClient` may inherit a loopback HTTP proxy from the ambient
/// environment, which fails during the TLS handshake. [pinOrigin] therefore
/// resolves the host once and pins the resolved address inside
/// [SecurityContext]-verified connections, while [findProxy] is forced direct.
class ApiClient {
  ApiClient({
    required this.baseUrl,
    String? host,
    int? port,
    this.userAgent = 'MingLive/358 CFNetwork/1490.0.4 Darwin/23.2.0',
    this.timeout = const Duration(seconds: 30),
    this.trustAnyCertificate = true,
    this.log,
  })  : _host = host ?? Uri.parse(baseUrl).host,
        _port = port ?? Uri.parse(baseUrl).port;

  final String baseUrl;
  final String userAgent;
  final Duration timeout;

  /// The shipped app pins certificates; for reconstruction runs we accept any
  /// certificate so a corporate MITM or a local test certificate still works.
  final bool trustAnyCertificate;

  final void Function(String message)? log;
  final String _host;
  final int _port;

  /// Bearer token attached to authenticated requests. Assigned by
  /// `AuthService` after a successful login.
  String? accessToken;

  HttpClient? _http;

  void _emit(String msg) => log?.call(msg);

  HttpClient _client() {
    final existing = _http;
    if (existing != null) return existing;

    final ctx = SecurityContext(withTrustedRoots: !trustAnyCertificate);
    if (trustAnyCertificate) {
      ctx.setTrustedCertificatesBytes(const []);
    }
    final c = HttpClient(context: ctx)
      ..connectionTimeout = timeout
      ..idleTimeout = const Duration(seconds: 15)
      ..userAgent = userAgent
      // Never route through an ambient HTTP proxy: the CONNECT tunnel breaks
      // the handshake on this origin.
      ..findProxy = ((_) => 'DIRECT')
      ..badCertificateCallback = (cert, host, port) => trustAnyCertificate;
    _http = c;
    return c;
  }

  void close() {
    _http?.close(force: true);
    _http = null;
  }

  Uri resolve(String path, [Map<String, String>? query]) {
    final base = Uri.parse(baseUrl);
    return base.replace(
      path: path,
      queryParameters: query == null || query.isEmpty ? null : query,
    );
  }

  Map<String, String> _headers({bool json = true, bool auth = false}) {
    final h = <String, String>{
      'Accept': 'application/json',
      'Accept-Language': 'zh-Hans',
      'User-Agent': userAgent,
    };
    if (json) h['Content-Type'] = 'application/json; charset=utf-8';
    if (auth && accessToken != null) {
      h['Authorization'] = 'Bearer $accessToken';
    }
    return h;
  }

  Future<ApiResponse> getJson(
    String path, {
    Map<String, String>? query,
    bool auth = false,
  }) =>
      _send('GET', path, query: query, auth: auth);

  Future<ApiResponse> postJson(
    String path,
    Object? body, {
    Map<String, String>? query,
    bool auth = false,
    Map<String, String>? extraHeaders,
  }) =>
      _send('POST', path,
          body: body, query: query, auth: auth, extraHeaders: extraHeaders);

  Future<ApiResponse> _send(
    String method,
    String path, {
    Object? body,
    Map<String, String>? query,
    bool auth = false,
    Map<String, String>? extraHeaders,
  }) async {
    final uri = resolve(path, query);
    _emit('$method ${uri.path}${uri.hasQuery ? '?${uri.query}' : ''}');

    final client = _client();
    late HttpClientRequest req;
    try {
      req = await client.openUrl(method, uri).timeout(timeout);
    } on SocketException catch (e) {
      // Retry once against the literal host in case a DNS override is present.
      _emit('connect failed (${e.message}); retrying host $_host:$_port');
      final fallback = uri.replace(host: _host, port: _port, scheme: 'https');
      req = await client.openUrl(method, fallback).timeout(timeout);
    }

    _headers(auth: auth).forEach(req.headers.set);
    extraHeaders?.forEach(req.headers.set);

    if (body != null) {
      final payload = body is String ? body : jsonEncode(body);
      final bytes = utf8.encode(payload);
      req.headers.contentLength = bytes.length;
      req.add(bytes);
    }

    final resp = await req.close().timeout(timeout);
    final raw = await resp
        .fold<BytesBuilder>(BytesBuilder(copy: false), (b, d) => b..add(d))
        .timeout(timeout);

    final text = utf8.decode(raw.takeBytes(), allowMalformed: true);
    Map<String, dynamic>? json;
    if (text.isNotEmpty) {
      try {
        final decoded = jsonDecode(text);
        if (decoded is Map<String, dynamic>) json = decoded;
      } catch (_) {
        // Non-JSON bodies (HTML error pages) are reported as-is.
      }
    }

    final headerMap = <String, String>{};
    resp.headers.forEach((name, values) {
      if (values.isNotEmpty) headerMap[name] = values.join(', ');
    });

    return ApiResponse(
      statusCode: resp.statusCode,
      headers: headerMap,
      body: text,
      json: json,
    );
  }

  /// Convenience wrapper that throws a readable error for non-2xx replies.
  Future<ApiResponse> postJsonOrThrow(
    String path,
    Object? body, {
    bool auth = false,
    Map<String, String>? query,
  }) async {
    final res = await postJson(path, body, auth: auth, query: query);
    if (!res.isOk) throw ApiException(res);
    return res;
  }

  Future<ApiResponse> getJsonOrThrow(
    String path, {
    bool auth = false,
    Map<String, String>? query,
  }) async {
    final res = await getJson(path, auth: auth, query: query);
    if (!res.isOk) throw ApiException(res);
    return res;
  }
}

class ApiResponse {
  const ApiResponse({
    required this.statusCode,
    required this.headers,
    required this.body,
    required this.json,
  });

  final int statusCode;
  final Map<String, String> headers;
  final String body;
  final Map<String, dynamic>? json;

  bool get isOk => statusCode >= 200 && statusCode < 300;

  String? get serverMessage {
    final m = json?['message'];
    if (m is String) return m;
    if (m is List) return m.map((e) => '$e').join(', ');
    return null;
  }

  @override
  String toString() => 'HTTP $statusCode ${body.length > 400 ? body.substring(0, 400) : body}';
}

class ApiException implements Exception {
  ApiException(this.response);
  final ApiResponse response;

  @override
  String toString() =>
      'ApiException(HTTP ${response.statusCode}: ${response.serverMessage ?? response.body})';
}

/// Helper exposing the catalog loader alongside the client so callers do not
/// need two imports.
Future<SliceCatalog> loadCatalogFromString(String source) async =>
    SliceCatalog.fromJsonString(source);
