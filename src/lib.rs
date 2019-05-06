extern crate schnorrkel;

// Copyright 2019 Soramitsu via https://github.com/Warchant/sr25519-crust
// Copyright 2019 Paritytech via https://github.com/paritytech/schnorrkel-js/
// Copyright 2019 @polkadot/wasm-schnorrkel authors & contributors
// This software may be modified and distributed under the terms
// of the Apache-2.0 license. See the LICENSE file for details.

// Originally developed (as a fork) in https://github.com/polkadot-js/schnorrkel-js/
// which was adpated from the initial https://github.com/paritytech/schnorrkel-js/
// forked at commit eff430ddc3090f56317c80654208b8298ef7ab3f

use schnorrkel::{
	derive::{ChainCode, Derivation, CHAIN_CODE_LENGTH},
	Keypair, MiniSecretKey, PublicKey, SecretKey, Signature,
};

use std::ptr;
use std::slice;

// We must make sure that this is the same as declared in the substrate source code.
const SIGNING_CTX: &'static [u8] = b"substrate";

/// ChainCode construction helper
fn create_cc(data: &[u8]) -> ChainCode {
	let mut cc = [0u8; CHAIN_CODE_LENGTH];

	cc.copy_from_slice(&data);

	ChainCode(cc)
}

/// Keypair helper function.
fn create_from_seed(seed: &[u8]) -> Keypair {
	match MiniSecretKey::from_bytes(seed) {
		Ok(mini) => return mini.expand_to_keypair(),
		Err(_) => panic!("Provided seed is invalid."),
	}
}

/// Keypair helper function.
fn create_from_pair(pair: &[u8]) -> Keypair {
	match Keypair::from_bytes(pair) {
		Ok(pair) => return pair,
		Err(_) => panic!(format!("Provided pair is invalid: {:?}", pair)),
	}
}

/// PublicKey helper
fn create_public(public: &[u8]) -> PublicKey {
	match PublicKey::from_bytes(public) {
		Ok(public) => return public,
		Err(_) => panic!("Provided public key is invalid."),
	}
}

/// SecretKey helper
fn create_secret(secret: &[u8]) -> SecretKey {
	match SecretKey::from_bytes(secret) {
		Ok(secret) => return secret,
		Err(_) => panic!("Provided private key is invalid."),
	}
}

/// Size of input SEED for derivation, bytes
pub const SR25519_SEED_SIZE: usize = 32;

/// Size of CHAINCODE, bytes
pub const SR25519_CHAINCODE_SIZE: usize = 32;

/// Size of SR25519 PUBLIC KEY, bytes
pub const SR25519_PUBLIC_SIZE: usize = 32;

/// Size of SR25519 PRIVATE (SECRET) KEY, which consists of [32 bytes key | 32 bytes nonce]
pub const SR25519_SECRET_SIZE: usize = 64;

/// Size of SR25519 SIGNATURE, bytes
pub const SR25519_SIGNATURE_SIZE: usize = 64;

/// Size of SR25519 KEYPAIR. [32 bytes key | 32 bytes nonce | 32 bytes public]
pub const SR25519_KEYPAIR_SIZE: usize = 96;

/// Perform a derivation on a secret
///
/// * keypair_out: pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
/// * pair_ptr: existing keypair - input buffer of SR25519_KEYPAIR_SIZE bytes
/// * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_derive_keypair_hard(
	keypair_out: *mut u8,
	pair_ptr: *const u8,
	cc_ptr: *const u8,
) {
	let pair = slice::from_raw_parts(pair_ptr, SR25519_KEYPAIR_SIZE);
	let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE);
	let kp = create_from_pair(pair)
		.secret
		.hard_derive_mini_secret_key(Some(create_cc(cc)), &[])
		.0
		.expand_to_keypair();

	ptr::copy(kp.to_bytes().as_ptr(), keypair_out, SR25519_KEYPAIR_SIZE);
}

/// Perform a derivation on a secret
///
/// * keypair_out: pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
/// * pair_ptr: existing keypair - input buffer of SR25519_KEYPAIR_SIZE bytes
/// * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_derive_keypair_soft(
	keypair_out: *mut u8,
	pair_ptr: *const u8,
	cc_ptr: *const u8,
) {
	let pair = slice::from_raw_parts(pair_ptr, SR25519_KEYPAIR_SIZE);
	let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE);
	let kp = create_from_pair(pair)
		.derived_key_simple(create_cc(cc), &[])
		.0;

	ptr::copy(kp.to_bytes().as_ptr(), keypair_out, SR25519_KEYPAIR_SIZE);
}

/// Perform a derivation on a publicKey
///
/// * pubkey_out: pre-allocated output buffer of SR25519_PUBLIC_SIZE bytes
/// * public_ptr: public key - input buffer of SR25519_PUBLIC_SIZE bytes
/// * cc_ptr: chaincode - input buffer of SR25519_CHAINCODE_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_derive_public_soft(
	pubkey_out: *mut u8,
	public_ptr: *const u8,
	cc_ptr: *const u8,
) {
	let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE);
	let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE);
	let p = create_public(public)
		.derived_key_simple(create_cc(cc), &[])
		.0;
	ptr::copy(p.to_bytes().as_ptr(), pubkey_out, SR25519_PUBLIC_SIZE);
}

/// Generate a key pair.
///
/// * keypair_out: keypair [32b key | 32b nonce | 32b public], pre-allocated output buffer of SR25519_KEYPAIR_SIZE bytes
/// * seed: generation seed - input buffer of SR25519_SEED_SIZE bytes
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_keypair_from_seed(keypair_out: *mut u8, seed_ptr: *const u8) {
	let seed = slice::from_raw_parts(seed_ptr, SR25519_SEED_SIZE);
	let kp = create_from_seed(seed);
	ptr::copy(kp.to_bytes().as_ptr(), keypair_out, SR25519_KEYPAIR_SIZE);
}

/// Sign a message
///
/// The combination of both public and private key must be provided.
/// This is effectively equivalent to a keypair.
///
/// * signature_out: output buffer of ED25519_SIGNATURE_SIZE bytes
/// * public_ptr: public key - input buffer of SR25519_PUBLIC_SIZE bytes
/// * secret_ptr: private key (secret) - input buffer of SR25519_SECRET_SIZE bytes
/// * message_ptr: Arbitrary message; input buffer of size message_length
/// * message_length: Length of a message
///
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_sign(
	signature_out: *mut u8,
	public_ptr: *const u8,
	secret_ptr: *const u8,
	message_ptr: *const u8,
	message_length: usize,
) {
	let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE);
	let secret = slice::from_raw_parts(secret_ptr, SR25519_SECRET_SIZE);
	let message = slice::from_raw_parts(message_ptr, message_length as usize);

	let sig = create_secret(secret).sign_simple(SIGNING_CTX, message, &create_public(public));

	ptr::copy(
		sig.to_bytes().as_ptr(),
		signature_out,
		SR25519_SIGNATURE_SIZE,
	);
}

/// Verify a message and its corresponding against a public key;
///
/// * signature_ptr: verify this signature
/// * message_ptr: Arbitrary message; input buffer of message_length bytes
/// * message_length: Message size
/// * public_ptr: verify with this public key; input buffer of SR25519_PUBLIC_SIZE bytes
///
/// * returned true if signature is valid, false otherwise
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn sr25519_verify(
	signature_ptr: *const u8,
	message_ptr: *const u8,
	message_length: usize,
	public_ptr: *const u8,
) -> bool {
	let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE);
	let signature = slice::from_raw_parts(signature_ptr, SR25519_SIGNATURE_SIZE);
	let message = slice::from_raw_parts(message_ptr, message_length as usize);
	let signature = match Signature::from_bytes(signature) {
		Ok(signature) => signature,
		Err(_) => return false,
	};

	create_public(public).verify_simple(SIGNING_CTX, message, &signature)
}

#[cfg(test)]
pub mod tests {
	extern crate rand;
	extern crate schnorrkel;

	use super::*;
	use hex_literal::{hex, hex_impl};
	use schnorrkel::{KEYPAIR_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};

	fn generate_random_seed() -> Vec<u8> {
		(0..32).map(|_| rand::random::<u8>()).collect()
	}

	#[test]
	fn can_create_keypair() {
		let seed = generate_random_seed();
		let mut keypair = [0u8; SR25519_KEYPAIR_SIZE];
		unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };

		assert_eq!(keypair.len(), KEYPAIR_LENGTH);
		println!("{:?}", keypair.to_vec());
	}

	#[test]
	fn creates_pair_from_known() {
		let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
		let expected = hex!("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a");
		let mut keypair = [0u8; SR25519_KEYPAIR_SIZE];
		unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

		assert_eq!(public, expected);
	}

	#[test]
	fn can_sign_message() {
		let seed = generate_random_seed();
		let mut keypair = [0u8; SR25519_KEYPAIR_SIZE];
		unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
		let private = &keypair[0..SECRET_KEY_LENGTH];
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
		let message = b"this is a message";

		let mut signature = [0u8; SR25519_SIGNATURE_SIZE];
		unsafe {
			sr25519_sign(
				signature.as_mut_ptr(),
				public.as_ptr(),
				private.as_ptr(),
				message.as_ptr(),
				message.len(),
			)
		};

		assert_eq!(signature.len(), SIGNATURE_LENGTH);
	}

	#[test]
	fn can_verify_message() {
		let seed = generate_random_seed();
		let mut keypair = [0u8; SR25519_KEYPAIR_SIZE];
		unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
		let private = &keypair[0..SECRET_KEY_LENGTH];
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
		let message = b"this is a message";
		let mut signature = [0u8; SR25519_SIGNATURE_SIZE];
		unsafe {
			sr25519_sign(
				signature.as_mut_ptr(),
				public.as_ptr(),
				private.as_ptr(),
				message.as_ptr(),
				message.len(),
			)
		};
		let is_valid = unsafe {
			sr25519_verify(
				signature.as_ptr(),
				message.as_ptr(),
				message.len(),
				public.as_ptr(),
			)
		};

		assert!(is_valid);
	}

	#[test]
	fn soft_derives_pair() {
		let cc = hex!("0c666f6f00000000000000000000000000000000000000000000000000000000"); // foo
		let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
		let expected = hex!("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a");
		let mut keypair = [0u8; SR25519_KEYPAIR_SIZE];
		let mut derived = [0u8; SR25519_KEYPAIR_SIZE];
		unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
		unsafe { sr25519_derive_keypair_soft(derived.as_mut_ptr(), keypair.as_ptr(), cc.as_ptr()) };
		let public = &derived[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

		assert_eq!(public, expected);
	}

	#[test]
	fn soft_derives_public() {
		let cc = hex!("0c666f6f00000000000000000000000000000000000000000000000000000000"); // foo
		let public = hex!("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a");
		let expected = hex!("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a");
		let mut derived = [0u8; SR25519_PUBLIC_SIZE];
		unsafe { sr25519_derive_public_soft(derived.as_mut_ptr(), public.as_ptr(), cc.as_ptr()) };

		assert_eq!(derived, expected);
	}

	#[test]
	fn hard_derives_pair() {
		let cc = hex!("14416c6963650000000000000000000000000000000000000000000000000000"); // Alice
		let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
		let expected = hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");
		let mut keypair = [0u8; SR25519_KEYPAIR_SIZE];
		let mut derived = [0u8; SR25519_KEYPAIR_SIZE];
		unsafe { sr25519_keypair_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
		unsafe { sr25519_derive_keypair_hard(derived.as_mut_ptr(), keypair.as_ptr(), cc.as_ptr()) };
		let public = &derived[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

		assert_eq!(public, expected);
	}
}
