import 'dart:convert';
import 'dart:isolate';

import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:hex/hex.dart';

class Pbkdf2 {
  /// Number of PBKDF2 iterations
  int iterations;

  Pbkdf2({
    this.iterations = 100000,
  });

  /// Compute PBKDF2-SHA256 hash of the secret.
  Future<String> sha256(
    String secret, {
    required List<int> nonce,
  }) {
    return _runIsolated(
      secret,
      nonce: nonce,
      hmac: cryptography.Hmac.sha256(),
      bits: 256,
    );
  }

  /// Compute PBKDF2-SHA512 hash of the secret.
  Future<String> sha512(
    String secret, {
    required List<int> nonce,
  }) {
    return _runIsolated(
      secret,
      nonce: nonce,
      hmac: cryptography.Hmac.sha512(),
      bits: 512,
    );
  }

  Future<String> _runIsolated(
    String secret, {
    required List<int> nonce,
    required cryptography.Hmac hmac,
    required int bits,
  }) async {
    // open a receive port
    ReceivePort receivePort = ReceivePort();

    // compute hash in isolate task
    await Isolate.spawn(
      _Pbkdf2.hash,
      _Arguments(
        secret: utf8.encode(secret),
        nonce: nonce,
        sendPort: receivePort.sendPort,
        iterations: iterations,
        algo: hmac,
        bits: bits,
      ),
    );

    // wait for the secret key
    final secretKey = await receivePort.first;

    // close the receive port
    receivePort.close();

    // return the secret key
    return secretKey;
  }
}

class _Arguments {
  List<int> secret;
  List<int> nonce;
  SendPort sendPort;
  int iterations;
  cryptography.Hmac algo;
  int bits;

  _Arguments({
    required this.secret,
    required this.nonce,
    required this.sendPort,
    required this.iterations,
    required this.algo,
    required this.bits,
  });
}

class _Pbkdf2 {
  /// Compute PBKDF2-SHA512 hash of the master password.
  static Future<void> hash(_Arguments args) async {
    // initialize the Pbkdf2 hasher
    final pbkdf2 = cryptography.Pbkdf2(
      macAlgorithm: args.algo,
      iterations: args.iterations,
      bits: args.bits,
    );

    // construct a secret key
    final secretKey = cryptography.SecretKey(args.secret);

    // compute a new secret key from a secret key and a nonce
    final newSecretKey = await pbkdf2.deriveKey(
      secretKey: secretKey,
      nonce: args.nonce,
    );

    // extract bytes from the secret key
    final newSecretKeyBytes = await newSecretKey.extractBytes();

    // convert bytes to hex string
    final newSecretKeyHex = HEX.encode(newSecretKeyBytes);

    // send the hex string to isolate port
    args.sendPort.send(newSecretKeyHex);
  }
}
