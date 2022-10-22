// import 'dart:convert';
// import 'dart:isolate';

// import 'package:cryptography/cryptography.dart' as cryptography;
// import 'package:hex/hex.dart';

// class AesCbc {
//   AesCbc();

//   //. Encrypt the clear text using AES-CBC 256 bits with HMAC-SHA256 authentication.
//   Future<String> encrypt(
//     String clearText, {
//     required String secretKey,
//     required List<int> nonce,
//   }) async {
//     // create a receive port
//     final receivePort = ReceivePort();

//     // create a new Isolate task
//     await Isolate.spawn(
//       _AesCbc.encrypt,
//       _EncryptArguments(
//         secretKey: secretKey,
//         nonce: nonce,
//         clearText: clearText,
//         sendPort: receivePort.sendPort,
//       ),
//     );

//     // wait for the secret box
//     final cryptography.SecretBox secretBox = await receivePort.first;

//     // close the receive port
//     receivePort.close();

//     // extract cipher text from the secret box
//     final cipherText = secretBox.cipherText;
//     // encode the cipher text as hex string
//     final cipherTextHex = HEX.encode(cipherText);

//     // return the cipher text
//     return cipherTextHex;
//   }
// }

// class _EncryptArguments {
//   String secretKey;
//   List<int> nonce;
//   String clearText;
//   SendPort sendPort;

//   _EncryptArguments({
//     required this.secretKey,
//     required this.nonce,
//     required this.clearText,
//     required this.sendPort,
//   });
// }

// class _DecryptArguments {
//   String secretKey;
//   List<int> nonce;
//   String cipher;
//   SendPort sendPort;

//   _DecryptArguments({
//     required this.secretKey,
//     required this.nonce,
//     required this.cipher,
//     required this.sendPort,
//   });
// }

// class _AesCbc {
//   /// Initialize the AES-CBC with 256 bit key and HMAC-SHA256 authentication.
//   static final aes =
//       cryptography.AesCbc.with256bits(macAlgorithm: cryptography.Hmac.sha256());

//   static Future<void> encrypt(_EncryptArguments args) async {
//     // convert clear text to bytes
//     final clearTextBytes = utf8.encode(args.clearText);

//     // decode the secret key
//     final secretKey = cryptography.SecretKey(HEX.decode(args.secretKey));

//     // encrypt the clear text
//     final secretBox = await aes.encrypt(
//       clearTextBytes,
//       secretKey: secretKey,
//       nonce: args.nonce,
//     );

//     // send the secret box to the Isolate task port
//     args.sendPort.send(secretBox);
//   }

//   static Future<void> decrypt(_DecryptArguments args) async {
//     // decode cipher hex string
//     final cipherBytes = HEX.decode(args.cipher);

//     // decode the secret key
//     final secretKey = cryptography.SecretKey(HEX.decode(args.secretKey));

//     // encrypt the clear text
//     final secretBox = await aes.decrypt(
//       clearTextBytes,
//       secretKey: secretKey,
//       nonce: args.nonce,
//     );

//     // send the secret box to the Isolate task port
//     args.sendPort.send(secretBox);
//   }
// }

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:pointycastle/export.dart';

class AesCbc {
  AesCbc();

  Future<String> encrypt(
    String clearText, {
    required String secretKey,
  }) async {
    final clearTextBytes = Uint8List.fromList(utf8.encode(clearText));
    final key = Uint8List.fromList(HEX.decode(secretKey));

    if (key.length != 32) {
      throw Exception('Secret key must be 32 bytes long');
    }

    var iv = Uint8List(16);
    var random = Random.secure();
    for (int i = 0; i < 16; i++) {
      iv[i] = random.nextInt(256);
    }

    var cipher = PaddedBlockCipherImpl(
      PKCS7Padding(),
      CBCBlockCipher(AESEngine()),
    );

    cipher.init(
      true /*encrypt*/,
      PaddedBlockCipherParameters<CipherParameters, CipherParameters>(
        ParametersWithIV<KeyParameter>(KeyParameter(key), iv),
        null,
      ),
    );

    final cipherTextBytes = cipher.process(clearTextBytes);

    final cipherTextHex = HEX.encode(iv + cipherTextBytes);

    return cipherTextHex;
  }

  Future<String> decrypt(
    String cipherText, {
    required String secretKey,
  }) async {
    var cipherTextBytes = Uint8List.fromList(HEX.decode(cipherText));
    final key = Uint8List.fromList(HEX.decode(secretKey));

    if (key.length != 32) {
      throw Exception('Secret key must be 32 bytes long');
    }

    final iv = cipherTextBytes.sublist(0, 16);
    cipherTextBytes = cipherTextBytes.sublist(16, cipherTextBytes.length);

    var cipher = PaddedBlockCipherImpl(
      PKCS7Padding(),
      CBCBlockCipher(AESEngine()),
    );

    cipher.init(
      false /*decrypt*/,
      PaddedBlockCipherParameters<CipherParameters, CipherParameters>(
        ParametersWithIV<KeyParameter>(KeyParameter(key), iv),
        null,
      ),
    );

    final clearTextBytes = cipher.process(cipherTextBytes);

    final clearText = utf8.decode(clearTextBytes);

    return clearText;
  }
}
