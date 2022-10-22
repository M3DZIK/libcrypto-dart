// import 'dart:convert';

// import 'package:libcrypto/libcrypto.dart';
// import 'package:test/test.dart';

// final clearText = 'string to be encrypted!';
// final password = 'password22222';
// final salt = utf8.encode('');

// void main() {
//   group('AES', () {
//     final pbkdf2 = Pbkdf2();
//     final aes = AesCbc();

//     test('encrypt', () async {
//       final secretKey = await pbkdf2.sha256(
//         password,
//         nonce: salt,
//       );

//       print(secretKey);

//       final cipherText = await aes.encrypt(
//         clearText,
//         secretKey: secretKey,
//         nonce: salt,
//       );

//       print(cipherText);
//     });

//     // test('decrypt', () async {
//     //   final secretKey = await pbkdf2.sha256(
//     //     password,
//     //     nonce: salt,
//     //   );

//     //   final cipherText = await aes.encrypt(
//     //     clearText,
//     //     secretKey: secretKey,
//     //     nonce: salt,
//     //   );

//     //   print(cipherText);
//     // });
//   });
// }

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
