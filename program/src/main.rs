#![no_main]
sp1_zkvm::entrypoint!(main);

use chacha_lib::chacha;

pub fn main() {
    let n = sp1_zkvm::io::read::<u32>();

    // let (a, b) = chacha(n);

    // Encode the public values of the program.
    let bytes = [0;10];

    sp1_zkvm::io::commit_slice(&bytes);
}
