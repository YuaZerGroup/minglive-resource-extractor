import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)
    registerDeviceKeyChannel()
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  /// Exposes the Keychain-backed device key pair under the same channel name the
  /// original build uses.
  ///
  /// The shipped app signs its secure requests with a device key that never
  /// leaves the device. This channel is the single seam where that key would be
  /// read or produced; wiring it up requires the original key material, so the
  /// handler reports unavailability instead of fabricating a key.
  private func registerDeviceKeyChannel() {
    guard let controller = window?.rootViewController as? FlutterViewController else {
      return
    }
    let channel = FlutterMethodChannel(
      name: "mingliveios/builtin_device_key",
      binaryMessenger: controller.binaryMessenger
    )
    channel.setMethodCallHandler { call, result in
      switch call.method {
      case "getKeyPair", "getPublicKey", "keyPair":
        result(FlutterError(
          code: "builtin_device_key_unavailable",
          message: "device key is not present in this build",
          details: nil
        ))
      case "sign":
        result(FlutterError(
          code: "builtin_device_key_unavailable",
          message: "device proof signer is not bound",
          details: nil
        ))
      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }
}
