fn main() {
    // Set soname for the shared library
    let version = env!("CARGO_PKG_VERSION");
    let major_version = version.split('.').next()
        .expect("Failed to parse major version from CARGO_PKG_VERSION");

    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libtruenas_rust_nss.so.{}", major_version);
}