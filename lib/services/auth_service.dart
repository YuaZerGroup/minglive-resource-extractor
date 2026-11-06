import 'dart:convert';

import '../core/protocol.dart';
import 'api_client.dart';

/// Membership snapshot returned inside the login payload.
class IosMembership {
  const IosMembership({required this.tier, this.expiresAt});

  final String tier;
  final DateTime? expiresAt;

  bool get isMember => tier.toUpperCase() == Protocol.tierMember;

  bool isActiveAt(DateTime now) =>
      expiresAt == null || expiresAt!.isAfter(now);

  bool get grantsMemberAccess => isMember && isActiveAt(DateTime.now());

  factory IosMembership.fromJson(Map<String, dynamic>? j) {
    if (j == null) return const IosMembership(tier: '');
    final exp = j['expiresAt'];
    return IosMembership(
      tier: (j['tier'] as String? ?? ''),
      expiresAt: exp is String ? DateTime.tryParse(exp)?.toLocal() : null,
    );
  }

  @override
  String toString() => 'IosMembership(tier=$tier, expiresAt=$expiresAt)';
}

class AccountUser {
  const AccountUser({
    required this.id,
    required this.username,
    required this.role,
    required this.status,
    required this.membership,
    this.email,
    this.nickname,
  });

  final String id;
  final String username;
  final String role;
  final String status;
  final IosMembership membership;
  final String? email;
  final String? nickname;

  factory AccountUser.fromJson(Map<String, dynamic> j) => AccountUser(
        id: j['id'] as String? ?? '',
        username: j['username'] as String? ?? '',
        role: j['role'] as String? ?? '',
        status: j['status'] as String? ?? '',
        email: j['email'] as String?,
        nickname: j['nickname'] as String?,
        membership: IosMembership.fromJson(
          j['iosMembership'] is Map<String, dynamic>
              ? j['iosMembership'] as Map<String, dynamic>
              : null,
        ),
      );

  @override
  String toString() =>
      'AccountUser($username, role=$role, status=$status, $membership)';
}

class Session {
  const Session({
    required this.accessToken,
    required this.refreshToken,
    required this.user,
    this.mustChangePassword = false,
  });

  final String accessToken;
  final String refreshToken;
  final AccountUser user;
  final bool mustChangePassword;

  /// Decodes the JWT payload without verifying the signature; used only to
  /// display expiry in the UI.
  Map<String, dynamic>? get jwtClaims {
    final parts = accessToken.split('.');
    if (parts.length != 3) return null;
    try {
      final doc = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(parts[1]))),
      );
      return doc is Map<String, dynamic> ? doc : null;
    } catch (_) {
      return null;
    }
  }

  DateTime? get expiresAt {
    final exp = jwtClaims?['exp'];
    if (exp is int) {
      return DateTime.fromMillisecondsSinceEpoch(exp * 1000).toLocal();
    }
    return null;
  }

  factory Session.fromJson(Map<String, dynamic> j) {
    final user = j['user'];
    return Session(
      accessToken: j['accessToken'] as String? ?? '',
      refreshToken: j['refreshToken'] as String? ?? '',
      mustChangePassword: j['mustChangePassword'] as bool? ?? false,
      user: AccountUser.fromJson(
        user is Map<String, dynamic> ? user : const {},
      ),
    );
  }
}

/// Login + session handling for the MingLive origin.
class AuthService {
  AuthService({required this.client, this.log});

  final ApiClient client;
  final void Function(String message)? log;

  void _emit(String m) => log?.call(m);

  /// `POST /auth/login` with `{ usernameOrEmail, password }`.
  ///
  /// The origin answers 201 Created with the token pair. Both field names were
  /// recovered from the server's own validation reply:
  /// `["usernameOrEmail must be a string","password must be a string"]`.
  Future<Session> login({
    required String usernameOrEmail,
    required String password,
  }) async {
    _emit('POST ${Protocol.pathLogin}');
    final res = await client.postJson(Protocol.pathLogin, {
      'usernameOrEmail': usernameOrEmail,
      'password': password,
    });
    if (!res.isOk || res.json == null) {
      throw ApiException(res);
    }
    final session = Session.fromJson(res.json!);
    client.accessToken = session.accessToken;
    _emit('login ok: user=${session.user.username} '
        'role=${session.user.role} membership=${session.user.membership.tier} '
        'tokenExp=${session.expiresAt}');
    return session;
  }

  Future<Session?> fetchAccount() async {
    final res = await client.getJson(Protocol.pathAccount, auth: true);
    if (!res.isOk || res.json == null) return null;
    return Session.fromJson(res.json!);
  }

  Future<void> logout() async {
    try {
      await client.postJson(Protocol.pathLogout, const <String, dynamic>{},
          auth: true);
    } catch (e) {
      _emit('logout failed: $e');
    } finally {
      client.accessToken = null;
    }
  }
}
