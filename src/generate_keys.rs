use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use ed25519_dalek::{Signature, SigningKey, Signer, VerifyingKey};
use rand_core::OsRng;

pub fn generate_identity_keys() -> (SigningKey, VerifyingKey) {
    let secret = SigningKey::generate(&mut OsRng);
    let public = secret.verifying_key();

    (secret, public)
}

pub fn generate_signed_prekey(identity_secret: &SigningKey) -> (StaticSecret, PublicKey, Signature) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let signature = identity_secret.sign(public.as_bytes());

    (secret, public, signature)
}

pub fn generate_onetime_prekeys(num_prekeys: usize) -> Vec<(i32 /*id*/, StaticSecret, PublicKey)> {
    let opks: Vec<(i32 /*id*/, StaticSecret, PublicKey)> = (0..num_prekeys)
        .map(|i| {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = PublicKey::from(&secret);
            (i as i32, secret, public)
        })
        .collect();

    return opks;
}