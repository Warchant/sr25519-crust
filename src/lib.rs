extern crate schnorrkel;

use schnorrkel::{
	Keypair, MiniSecretKey, PublicKey, SecretKey, Signature,
	derive::{Derivation, ChainCode, CHAIN_CODE_LENGTH},
};

// We must make sure that this is the same as declared in the substrate source code.
pub const SIGNING_CTX: &'static [u8] = b"substrate";


#[no_mangle]
pub extern "C" fn test() {
	println!("hello world");
}
