import 'dart:convert';
import 'dart:typed_data';

import 'package:libcrypto/libcrypto.dart';
import 'package:test/test.dart';

final secret = 'hello world';
final salt = Uint8List.fromList(utf8.encode('salt'));

void main() {
  group('Pbkdf2', () {
    // initialize the PBKDF2 hasher
    final pbkdf2 = Pbkdf2(iterations: 1000);

    // test sha256 hashing
    test('sha256', () async {
      final hash = await pbkdf2.sha256(secret, salt);

      expect(
        hash,
        equals(
          '27426946a796b9a62bc53fba7157961905e4bdd0af2203d6eaf6dd4b64942def',
        ),
      );
    });

    // test sha512 hashing
    test('sha512', () async {
      final hash = await pbkdf2.sha512(secret, salt);

      expect(
        hash,
        equals(
          '883f5fb301ff684a2e92fdfc1754241bb2dd3eb6af53e5bd7e6c9eb2df7ccb7783f40872b5d3dd5c2915a519f008a92c4c2093e8a589e59962cf1e33c8706ca9',
        ),
      );
    });
  });
}
