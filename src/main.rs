mod exchange;
mod key_structs;
mod test;
mod generate_keys;

use x25519_dalek::{StaticSecret, PublicKey};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

fn main() {
    test::x3dh();
}
