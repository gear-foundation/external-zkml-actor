fn main() {
    #[cfg(feature = "asm")]
    if gstd::env::consts::ARCH != "x86_64" {
        eprintln!("Currently feature `asm` can only be enabled on x86_64 arch.");
        gstd::process::exit(1);
    }
}
