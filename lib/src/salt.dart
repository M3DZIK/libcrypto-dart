import 'dart:math';
import 'dart:typed_data';

class Salt {
  /// Length of the salt to be generated.
  int length;

  Salt(this.length);

  // Generate a random salt.
  Uint8List generate() {
    // allocate an array of zero bytes
    var salt = Uint8List(length);

    // create a cryptographically secure random number generator.
    var random = Random.secure();

    // fill the array with random bytes
    for (int i = 0; i < length; i++) {
      salt[i] = random.nextInt(256);
    }

    // return the salt
    return salt;
  }
}
