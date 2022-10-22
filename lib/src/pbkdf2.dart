import 'dart:convert';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:pointycastle/pointycastle.dart';

class Pbkdf2 {
  /// Number of PBKDF2 iterations.
  int iterations;

  Pbkdf2({
    required this.iterations,
  });

  /// Compute a SHA-256/HMAC/PBKDF2 hash of the secret data.
  Future<String> sha256(String data, Uint8List salt) async {
    // initialize the key derivator
    final hasher = KeyDerivator('SHA-256/HMAC/PBKDF2');

    return _compute(data, salt: salt, hasher: hasher, length: 32);
  }

  /// Compute a SHA-512/HMAC/PBKDF2 hash of the secret data.
  Future<String> sha512(String data, Uint8List salt) async {
    // initialize the key derivator
    final hasher = KeyDerivator('SHA-512/HMAC/PBKDF2');

    return _compute(data, salt: salt, hasher: hasher, length: 64);
  }

  Future<String> _compute(
    String data, {
    required Uint8List salt,
    required KeyDerivator hasher,
    required int length,
  }) async {
    // initialize the hasher
    hasher.init(Pbkdf2Parameters(salt, iterations, length));

    // open a receive port
    ReceivePort receivePort = ReceivePort();

    // process hash in an isolate task
    await Isolate.spawn(
      (SendPort sendPort) {
        // compute the hash
        final hash = hasher.process(Uint8List.fromList(utf8.encode(data)));

        // encode the hash into a hex string
        final hexHash = HEX.encode(hash);

        // send the hash to the isolate send port
        sendPort.send(hexHash);
      },
      receivePort.sendPort,
    );

    // get the hash from the isolate task
    final hash = await receivePort.first;

    // returns the hash
    return hash;
  }
}
