import 'dart:convert';
import 'dart:typed_data';

import 'package:libcrypto/libcrypto.dart';
import 'package:test/test.dart';

final secret = 'secret passphrase';
final clearText = 'hello world';
final salt = Uint8List.fromList(utf8.encode('salt'));

void main() {
  group('Aes', () {
    // initialize the PBKDF2 hasher
    final pbkdf2 = Pbkdf2(iterations: 1000);
    final aesCbc = AesCbc();

    test('encrypt', () async {
      final secretKey = await pbkdf2.sha256(secret, salt);

      final cipherText = await aesCbc.encrypt(clearText, secretKey: secretKey);

      final decrypt = await aesCbc.decrypt(cipherText, secretKey: secretKey);

      expect(clearText, equals(decrypt));
    });

    test('decrypt', () async {
      final secretKey = await pbkdf2.sha256(secret, salt);
      final cipherText =
          'ae77d812f4494a766a94b5dff8e7aa3c8408544b9fd30cd13b886cc5dd1b190e';

      final clearText = await aesCbc.decrypt(cipherText, secretKey: secretKey);

      expect(clearText, equals('hello world'));
    });
  });
}
