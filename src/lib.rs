extern crate schnorrkel;

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

pub const SR25519_SEED_SIZE: usize = 32;
pub const SR25519_CHAINCODE_SIZE: usize = 32;
pub const SR25519_PUBLIC_SIZE: usize = 32;
pub const SR25519_SECRET_SIZE: usize = 64;
pub const SR25519_SIGNATURE_SIZE: usize = 64;
pub const SR25519_KEYPAIR_SIZE: usize = 96;

/// Perform a derivation on a secret
///
/// * secret: UIntArray with 64 bytes
/// * cc: UIntArray with 32 bytes
///
/// returned vector the derived keypair as a array of 96 bytes
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn ext_sr_derive_keypair_hard(
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
/// * secret: UIntArray with 64 bytes
/// * cc: UIntArray with 32 bytes
///
/// returned vector the derived keypair as a array of 96 bytes
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn ext_sr_derive_keypair_soft(
	pair_ptr: *const u8,
	cc_ptr: *const u8,
) -> *mut u8 {
	let pair = slice::from_raw_parts(pair_ptr, SR25519_KEYPAIR_SIZE);
	let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE);
	create_from_pair(pair)
		.derived_key_simple(create_cc(cc), &[])
		.0
		.to_bytes()
		.as_mut_ptr()
}

/// Perform a derivation on a publicKey
///
/// * pubkey: UIntArray with 32 bytes
/// * cc: UIntArray with 32 bytes
///
/// returned vector is the derived publicKey as a array of 32 bytes
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn ext_sr_derive_public_soft(
	public_ptr: *const u8,
	cc_ptr: *const u8,
) -> *mut u8 {
	let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE);
	let cc = slice::from_raw_parts(cc_ptr, SR25519_CHAINCODE_SIZE);
	create_public(public)
		.derived_key_simple(create_cc(cc), &[])
		.0
		.to_bytes()
		.as_mut_ptr()
}

/// Generate a key pair.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (64 bytes)
/// followed by the public key (32) bytes, total size is 96 bytes.
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn ext_sr_from_seed(keypair_out: *mut u8, seed_ptr: *const u8) {
	let seed = slice::from_raw_parts(seed_ptr, SR25519_SEED_SIZE);
	let kp = create_from_seed(seed);
	ptr::copy(kp.to_bytes().as_ptr(), keypair_out, SR25519_KEYPAIR_SIZE);
}

/// Sign a message
///
/// The combination of both public and private key must be provided.
/// This is effectively equivalent to a keypair.
///
/// * public: UIntArray with 32 element
/// * private: UIntArray with 64 element
/// * message: Arbitrary length UIntArray
/// * message_length: Length of a message
///
/// * returned vector is the signature consisting of 64 bytes.
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn ext_sr_sign(
	public_ptr: *const u8,
	secret_ptr: *const u8,
	message_ptr: *const u8,
	message_length: usize,
) -> *mut u8 {
	let public = slice::from_raw_parts(public_ptr, SR25519_PUBLIC_SIZE);
	let secret = slice::from_raw_parts(secret_ptr, SR25519_SECRET_SIZE);
	let message = slice::from_raw_parts(message_ptr, message_length as usize);

	create_secret(secret)
		.sign_simple(SIGNING_CTX, message, &create_public(public))
		.to_bytes()
		.as_mut_ptr()
}

/// Verify a message and its corresponding against a public key;
///
/// * signature: UIntArray with 64 element
/// * message: Arbitrary length message
/// * message_length: Message size
/// * pubkey: UIntArray with 32 element
///
/// * returned true if signature is valid, false otherwise
#[allow(unused_attributes)]
#[no_mangle]
pub unsafe extern "C" fn ext_sr_verify(
	signature_ptr: *const u8,
	message_ptr: *const u8,
	message_length: usize,
	public_ptr: *const u8,
) -> bool {
	let public = slice::from_raw_parts(public_ptr, 32);
	let signature = slice::from_raw_parts(signature_ptr, 64);
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
		unsafe { ext_sr_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };

		assert!(keypair.len() == KEYPAIR_LENGTH);
		println!("{:?}", keypair.to_vec());
	}

	#[test]
	fn creates_pair_from_known() {
		let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
		let expected = hex!("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a");
		let mut keypair = [0u8; SR25519_KEYPAIR_SIZE];
		unsafe { ext_sr_from_seed(keypair.as_mut_ptr(), seed.as_ptr()) };
		let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

		assert_eq!(public, expected);
	}

	// #[test]
	// fn can_sign_message() {
	// 	let seed = generate_random_seed();
	// 	let keypair_ptr = unsafe { ext_sr_from_seed(seed.as_ptr()) };
	// 	let keypair = unsafe { slice::from_raw_parts(keypair_ptr, SR25519_KEYPAIR_SIZE) };
	// 	let private = &keypair[0..SECRET_KEY_LENGTH];
	// 	let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
	// 	let message = b"this is a message";
	// 	let signature_ptr = unsafe {
	// 		ext_sr_sign(
	// 			public.as_ptr(),
	// 			private.as_ptr(),
	// 			message.as_ptr(),
	// 			message.len(),
	// 		)
	// 	};
	//
	// 	let signature = unsafe { slice::from_raw_parts(signature_ptr, SR25519_SIGNATURE_SIZE) };
	//
	// 	assert!(signature.len() == SIGNATURE_LENGTH);
	// }

	// #[test]
	// fn can_verify_message() {
	// 	let seed = generate_random_seed();
	// 	let keypair_ptr = unsafe { ext_sr_from_seed(seed.as_ptr()) };
	// 	let keypair = unsafe { slice::from_raw_parts(keypair_ptr, SR25519_KEYPAIR_SIZE) };
	// 	let private = &keypair[0..SECRET_KEY_LENGTH];
	// 	let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
	// 	let message = b"this is a message";
	// 	let signature_ptr = unsafe {
	// 		ext_sr_sign(
	// 			public.as_ptr(),
	// 			private.as_ptr(),
	// 			message.as_ptr(),
	// 			message.len(),
	// 		)
	// 	};
	// 	let is_valid = unsafe {
	// 		ext_sr_verify(
	// 			signature_ptr,
	// 			message.as_ptr(),
	// 			message.len(),
	// 			public.as_ptr(),
	// 		)
	// 	};
	//
	// 	assert!(is_valid);
	// }

	// #[test]
	// fn soft_derives_pair() {
	// 	let cc = hex!("0c666f6f00000000000000000000000000000000000000000000000000000000"); // foo
	// 	let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
	// 	let expected = hex!("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a");
	// 	let keypair_ptr = unsafe { ext_sr_from_seed(seed.as_ptr()) };
	// 	let derived_ptr = unsafe { ext_sr_derive_keypair_soft(keypair_ptr, cc.as_ptr()) };
	// 	let derived = unsafe { slice::from_raw_parts(derived_ptr, SR25519_KEYPAIR_SIZE) };
	// 	let public = &derived[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
	//
	// 	assert_eq!(public, expected);
	// }

	// #[test]
	// fn soft_derives_public() {
	// 	let cc = hex!("0c666f6f00000000000000000000000000000000000000000000000000000000"); // foo
	// 	let public = hex!("46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a");
	// 	let expected = hex!("40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a");
	// 	let derived_ptr = unsafe { ext_sr_derive_public_soft(public.as_ptr(), cc.as_ptr()) };
	// 	let derived = unsafe { slice::from_raw_parts(derived_ptr, SR25519_PUBLIC_SIZE) };
	//
	// 	assert_eq!(derived, expected);
	// }

	// #[test]
	// fn hard_derives_pair() {
	// 	let cc = hex!("14416c6963650000000000000000000000000000000000000000000000000000"); // Alice
	// 	let seed = hex!("fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
	// 	let expected = hex!("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");
	// 	let keypair_ptr = unsafe { ext_sr_from_seed(seed.as_ptr()) };
	// 	let derived_ptr = unsafe { ext_sr_derive_keypair_hard(keypair_ptr, cc.as_ptr()) };
	// 	let derived = unsafe { slice::from_raw_parts(derived_ptr, SR25519_KEYPAIR_SIZE) };
	// 	let public = &derived[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];
	//
	// 	assert_eq!(public, expected);
	// }
}
