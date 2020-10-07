use std::env;
use cbindgen::Config;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(Config::from_file("./cbindgen.toml").expect("Parsing config failed"))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("./include/_25519/_25519.h");
}
