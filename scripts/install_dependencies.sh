#!/bin/bash

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly
source $HOME/.cargo/env
rustup install nightly
rustup default nightly
cargo install --force cbindgen
