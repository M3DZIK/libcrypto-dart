import 'package:cryptography/cryptography.dart' as cryptography;

class AesCbc {
  AesCbc();
}

class _AesCbc {
  /// Initialize the AES-CBC with 256 bit key and HMAC-SHA256 authentication.
  static final aes =
      cryptography.AesCbc.with256bits(macAlgorithm: cryptography.Hmac.sha256());

  static Future<void> encrypt() async {}
}
