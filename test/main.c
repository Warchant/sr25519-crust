#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/// The length of a Ristretto Schnorr `MiniSecretKey`, in bytes.
#define MINI_SECRET_KEY_LENGTH 32

/// The length of a Ristretto Schnorr `PublicKey`, in bytes.
#define PUBLIC_KEY_LENGTH 32

/// The length of the "key" portion of a Ristretto Schnorr secret key, in bytes.
#define SECRET_KEY_KEY_LENGTH 32

/// The length of the "nonce" portion of a Ristretto Schnorr secret key, in
/// bytes.
#define SECRET_KEY_NONCE_LENGTH 32

/// The length of a Ristretto Schnorr key, `SecretKey`, in bytes.
#define SECRET_KEY_LENGTH (SECRET_KEY_KEY_LENGTH + SECRET_KEY_NONCE_LENGTH)

/// The length of an Ristretto Schnorr `Keypair`, in bytes.
#define KEYPAIR_LENGTH (SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH)

extern uint8_t *ext_sr_from_seed(uint8_t *seed);
extern uint8_t *
ext_sr_derive_keypair_hard(const uint8_t *pair_ptr,
                           const uint8_t *cc_ptr); // res is 96 bytes long

uint8_t *hex(const char *hex_s) {
  const char *pos = hex_s;
  uint8_t *val = malloc(strlen(hex_s) / 2);

  /* WARNING: no sanitization or error-checking whatsoever */
  for (size_t count = 0; count < strlen(hex_s) / 2; count++) {
    sscanf(pos, "%2hhx", &val[count]);
    pos += 2;
  }

  return val;
}

int main() {
  uint8_t *cc = hex("14416c6963650000000000000000000000000000000000000000000000000000"); // Alice
  uint8_t *seed = hex("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
  uint8_t *expected = hex("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");
  uint8_t *keypair = ext_sr_from_seed(seed);

  uint8_t *derived_ptr = ext_sr_derive_keypair_hard(keypair, cc);

  return 0;
}
