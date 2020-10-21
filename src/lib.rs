// Copyright 2019 Soramitsu via https://github.com/Warchant/sr25519-crust
// Copyright 2019 Paritytech via https://github.com/paritytech/schnorrkel-js/
// Copyright 2019 @polkadot/wasm-schnorrkel authors & contributors
// This software may be modified and distributed under the terms
// of the Apache-2.0 license. See the LICENSE file for details.

// Originally developed (as a fork) in https://github.com/polkadot-js/schnorrkel-js/
// which was adopted from the initial https://github.com/paritytech/schnorrkel-js/
// forked at commit eff430ddc3090f56317c80654208b8298ef7ab3f

#![warn(missing_docs)] // refuse to compile if documentation is missing
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
// for enum variants
#![allow(unused_variables)]
#![allow(non_snake_case)]
#![warn(future_incompatible)]

//!
//! Glue code to generate C headers for sr25519 and ed25519 rust implementations
//!


/// Glue code for Dalek's Ed25519 implementation
pub mod ed25519;

/// Glue code for Schnorrkel
pub mod sr25519;

