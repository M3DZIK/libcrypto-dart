import 'dart:typed_data';

import 'package:libcrypto/libcrypto.dart';

void main() async {
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
