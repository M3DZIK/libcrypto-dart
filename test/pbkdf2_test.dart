import 'dart:convert';

import 'package:libcrypto/libcrypto.dart';
import 'package:test/test.dart';

final secret = 'string to be hashed';
final salt = utf8.encode('this is a salt');

void main() {
  group('Pbkdf2', () {
    final pbkdf2 = Pbkdf2();

    test('sha256', () async => await pbkdf2.sha256(secret, nonce: salt));
    test('sha512', () async => await pbkdf2.sha512(secret, nonce: salt));
  });
}
