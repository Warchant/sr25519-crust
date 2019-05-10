[![Build Status](https://travis-ci.org/Warchant/sr25519-crust.svg?branch=master)](https://travis-ci.org/Warchant/sr25519-crust)

# sr25519-crust

C bindings over [RUST implementation of sr25519 (schnorrkel)](https://github.com/w3f/schnorrkel) - Schnorr-on-ristretto255 scheme.

## Build

1. Install rust compiler (nightly), `cargo`, `cbindgen`:
    ```bash
    curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly
    source $HOME/.cargo/env
    rustup install nightly
    rustup default nightly
    cargo install --force cbindgen
    ```
2. `mkdir build && cd build`
3. Options;
   - `-DTESTING=[ON|OFF]` - enable or disable build of tests.
   - `-DCMAKE_BUILD_TYPE=[Release|Debug]` - select build type.
   - `-DBUILD_SHARED_LIBS=[TRUE|FALSE]` - build shared/static library. 
   
   ```bash
   cmake .. -DCMAKE_BUILD_TYPE=Release
   ```
4. Build and install library: 
   ```
   sudo make install
   ```

