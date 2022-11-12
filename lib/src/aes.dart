import 'dart:convert';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:libcrypto/src/salt.dart';
import 'package:pointycastle/export.dart';

class AesCbc {
  AesCbc();

  /// Encrypt the clear text using AES-CBC.
  ///
  /// Key must be 256-bit (32 bytes) long.
  Future<String> encrypt(
    String clearText, {
    required String secretKey,
  }) async {
    // encode the secret key to a bytes array
    final key = Uint8List.fromList(HEX.decode(secretKey));

    // key must be 256-bit (32 bytes) long
    if (key.length != 32) {
      throw Exception('Secret key must be 32 bytes long');
    }

    // generate a random initialization vector
    var iv = Salt(16).generate();

    // encode the clear text as a byte slice
    final clearTextBytes = Uint8List.fromList(utf8.encode(clearText));

    // encrypt the clear text
    final cipherTextBytes = await _process(
      forEncryption: true,
      key: key,
      iv: iv,
      data: clearTextBytes,
    );

    // encode the cipher text as a hex string
    final cipherTextHex = HEX.encode(iv + cipherTextBytes);

    // returns the cipher text
    return cipherTextHex;
  }

  /// Decrypt the cipher text using AES-CBC.
  ///
  /// Cipher text schema: [iv (16 bytes long) + cipher text] in a hex string
  Future<String> decrypt(
    String cipherText, {
    required String secretKey,
  }) async {
    // encode the secret key to a bytes array
    final key = Uint8List.fromList(HEX.decode(secretKey));

    // key must be 256-bit (32 bytes) long
    if (key.length != 32) {
      throw Exception('Secret key must be 32 bytes long');
    }

    // encode the cipher text from hex string to bytes slice
    var cipherTextBytes = Uint8List.fromList(HEX.decode(cipherText));

    // get initialization vector from the cipher text
    final iv = cipherTextBytes.sublist(0, 16);
    // remove initialization vector from the cipher text
    cipherTextBytes = cipherTextBytes.sublist(16, cipherTextBytes.length);

    // decrypt the cipher text
    final clearTextBytes = await _process(
      forEncryption: false,
      key: key,
      iv: iv,
      data: cipherTextBytes,
    );

    // encode the clear text to a string
    final clearText = utf8.decode(clearTextBytes);

    // returns the clear ext
    return clearText;
  }

  Future<Uint8List> _process({
    required bool forEncryption,
    required Uint8List key,
    required Uint8List iv,
    required Uint8List data,
  }) async {
    // create the padded block cipher
    var cipher = PaddedBlockCipher('AES/CBC/PKCS7');

    // initialize the cipher
    cipher.init(
      forEncryption,
      PaddedBlockCipherParameters<CipherParameters, CipherParameters>(
        ParametersWithIV<KeyParameter>(KeyParameter(key), iv),
        null,
      ),
    );

    // open a receive port
    ReceivePort receivePort = ReceivePort();

    // process hash in an isolate task
    await Isolate.spawn(
      (SendPort sendPort) {
        // process a whole block of data
        try {
          final output = cipher.process(data);

          sendPort.send(output);
        } catch (err) {
          sendPort.send(err.toString());
        }
      },
      receivePort.sendPort,
    );

    // get the hash from the isolate task
    final output = await receivePort.first;

    if (output is String) {
      throw Exception(output);
    }

    // returns the output
    return output;
  }
}
