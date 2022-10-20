import 'dart:convert';

import 'package:libcrypto/libcrypto.dart';

void main() async {
  var secret = 'P@ssw0rd1234!';
  var salt = utf8.encode('example@example.com');

  var hasher = Pbkdf2();

  var sha256Hash = await hasher.sha256(secret, nonce: salt);
  print('sha256: $sha256Hash');

  var sha512Hash = await hasher.sha512(secret, nonce: salt);
  print('sha512: $sha512Hash');
}
