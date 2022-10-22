import 'dart:convert';
import 'dart:typed_data';

import 'package:libcrypto/libcrypto.dart';

void main() async {
  var secret = 'P@ssw0rd1234!';
  var salt = Uint8List.fromList(utf8.encode('example@example.com'));

  var hasher = Pbkdf2(iterations: 1000000);

  var sha256Hash = await hasher.sha256(secret, salt);
  print('sha256: $sha256Hash');

  var sha512Hash = await hasher.sha512(secret, salt);
  print('sha512: $sha512Hash');
}
