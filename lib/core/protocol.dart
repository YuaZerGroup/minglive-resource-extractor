/// MingLive builtin-slice protocol constants.
///
/// Everything in this file was recovered from the shipped iOS build
/// (`Payload/Runner.app/Frameworks/App.framework/App`, a Dart AOT snapshot)
/// together with the live service responses at `https://app.minglive.cn:3001`.
///
/// Recovered wire contract:
///   * `POST /auth/login`      -> { accessToken, refreshToken, user{ iosMembership.tier } }
///   * `GET  /transport/keys`  -> { payload: b64url(manifest), signature: b64url(ed25519) }
///   * `POST /features/secure-list`
///   * `POST /features/secure-session`
///   * `POST /features/secure-builtin-slices-<suffix>`
///
/// Secure endpoints reject bare JSON with `{"message":"Invalid secure request"}`.
/// That message is absent from the client binary, i.e. it is produced only by the
/// server-side guard, which means the client always sends a signed *envelope*.
class Protocol {
  Protocol._();

  // ---------------------------------------------------------------- transport
  static const String defaultBaseUrl = 'https://app.minglive.cn:3001';

  /// Pinned origin host. The service resolves to a single IPv4; keeping the host
  /// here lets callers force SNI even when a local proxy rewrites DNS.
  static const String host = 'app.minglive.cn';
  static const int port = 3001;

  static const String userAgent =
      'MingLive/358 CFNetwork/1490.0.4 Darwin/23.2.0';

  // --------------------------------------------------------------------- auth
  static const String pathLogin = '/auth/login';
  static const String pathAccount = '/auth/account';
  static const String pathLogout = '/auth/logout';

  // ------------------------------------------------------------------ keys
  static const String pathTransportKeys = '/transport/keys';

  // ---------------------------------------------------------------- features
  static const String pathSecureList = '/features/secure-list';
  static const String pathSecureSession = '/features/secure-session';

  /// The slice endpoint is built as `<prefix><suffix>`; the suffix is a runtime
  /// identifier (catalog version / content key id) supplied by the server.
  static const String pathSlicesPrefix = '/features/secure-builtin-slices-';

  // ------------------------------------------------------------ secure batch
  static const String pathSecureBatch = '/client-events/secure-batch';

  // ------------------------------------------------------- protocol schemas
  /// Catalog schema string shipped inside `assets/builtin-slices/catalog.json`.
  static const String catalogSchema = 'minglive-builtin-slices-v2';

  /// Manifest returned by `GET /transport/keys` (base64url inside `payload`).
  static const String transportKeysSchema = 'minglive-transport-keys-v1';

  /// Per-asset cipher envelope identifier.
  static const String sliceWrapSchema = 'minglive-slice-wrap-v2';

  /// Delivery envelope identifier for assembled remote payloads.
  static const String sliceDeliverySchema = 'minglive-slice-delivery-v2';

  /// Device proof schema produced by the native channel.
  static const String deviceProofSchema = 'minglive-builtin-device-proof-v1';

  /// Key-derivation salt for the remote content key.
  static const String remoteContentSalt = 'MINGLIVE-REMOTE-CONTENT-SALT-v1';

  /// FF1 tweak/domain prefix for the remote cipher stream.
  static const String remoteContentFf1Prefix = 'MINGLIVE-REMOTE-CONTENT-FF1-v3:';

  // ------------------------------------------------------- native channels
  /// MethodChannel exposing the Keychain-backed device key pair.
  static const String channelDeviceKey = 'mingliveios/builtin_device_key';

  // ------------------------------------------------------------ on-disk form
  /// Magic that prefixes every `.part` slice file.
  static const List<int> sliceMagic = [0x4D, 0x4C, 0x41, 0x31]; // "MLA1"

  static const String sliceMagicString = 'MLA1';
  static const String sliceSuffix = '.part';
  static const String catalogAssetPath = 'assets/builtin-slices/catalog.json';
  static const String catalogAssetDir = 'assets/builtin-slices/';

  // ------------------------------------------------------------- access tier
  static const String tierMember = 'MEMBER';
  static const String tierFree = 'FREE';

  // ------------------------------------------------------------ error text
  static const String errInvalidEnvelope = 'Invalid envelope';
  static const String errExpectedEnvelope = 'Expected envelope, got nothing';
  static const String errExpectedEnvelopeList = 'Expected envelope List, got ';
  static const String errTransportKeySignature = 'Invalid transport key signature';
  static const String errTransportKeyManifest = 'Invalid transport key manifest';
  static const String errTransportKeyEntry = 'Invalid transport key entry';
  static const String errTransportKeyList = 'Invalid transport key list';
  static const String errExpiredTransportKey = 'Expired transport key manifest';
  static const String errMissingActiveKey = 'Missing active transport key';
  static const String errSecureResponse = 'Invalid secure response';
  static const String errSecureKeyMismatch = 'Secure response key mismatch';
  static const String errInvalidSecureSession = 'Invalid secure session';
  static const String errEncryptedHeader = 'Invalid encrypted asset header';
  static const String errRemoteCipherEmpty = 'remote ciphertext is empty';
  static const String errRemoteContentEmpty = 'remote content is empty';
}
