import 'dart:convert';
import 'dart:typed_data';

import 'package:libcrypto/libcrypto.dart';

void main() async {
  print('Pbkdf2:');
  await pbkdf2Example();

  print('\nAES-CBC:');
  await aesCbcExample();
}

Future<void> pbkdf2Example() async {
  final secret = 'P@ssw0rd1234!';
  final salt = Uint8List.fromList(utf8.encode('example@example.com'));

  final hasher = Pbkdf2(iterations: 1000);

  final sha256Hash = await hasher.sha256(secret, salt);
  print('sha256: $sha256Hash');

  final sha512Hash = await hasher.sha512(secret, salt);
  print('sha512: $sha512Hash');
}

Future<void> aesCbcExample() async {
  final clearText = 'hello world';
  final secret = 'P@ssw0rd1234!';
  final salt = Uint8List.fromList(Salt(20).generate());

  final aesCbc = AesCbc();
  final pbkdf2Hasher = Pbkdf2(iterations: 100);

  final secretKey = await pbkdf2Hasher.sha256(secret, salt);

  // encrypt the clear text
  final cipherText = await aesCbc.encrypt(clearText, secretKey: secretKey);

  print('Encrypted: $cipherText');

  final decryptedText = await aesCbc.decrypt(cipherText, secretKey: secretKey);

  print('Decrypted: $decryptedText');
}
