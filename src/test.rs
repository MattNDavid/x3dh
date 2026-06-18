use crate::key_structs;
use crate::exchange;
use crate::generate_keys;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use ed25519_dalek::{Signature, SigningKey, Signer, Verifier, VerifyingKey};
use rand_core::OsRng;

struct Bob {
    identity_secret: SigningKey,
    identity_public: VerifyingKey,
    static_id_secret: StaticSecret,
    static_id_public: PublicKey,
    signed_prekey_secret: StaticSecret,
    signed_prekey_public: PublicKey,
    signature: Signature,
    one_time_prekey_secret: StaticSecret,
    one_time_prekey_public: PublicKey,
}
struct Alice {
    identity_secret: SigningKey,
    identity_public: VerifyingKey,
    static_id_secret: StaticSecret,
    static_id_public: PublicKey,
    ephemeral_secret: StaticSecret,
    ephemeral_public: PublicKey,
}
pub fn x3dh() -> bool {
    let bob = init_bob();
    let alice = init_alice();

    let alice_shared_secret = alice_shared_secret(&alice, &bob).unwrap();
    let bob_shared_secret = bob_shared_secret(&bob, &alice).unwrap();

    assert_eq!(alice_shared_secret, bob_shared_secret);

    return true;
}

fn alice_shared_secret(alice: &Alice, bob: &Bob) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    //Verify prekey signature
    if !verify_prekey_signature(&bob.identity_public, &bob.signed_prekey_public, &bob.signature) {
        return Err("Invalid prekey signature".into());
    }

    //Alice compute shared secret
    let dh1 = alice.static_id_secret.diffie_hellman(&bob.signed_prekey_public);
    let dh2 = alice.ephemeral_secret.diffie_hellman(&bob.static_id_public);
    let dh3 = alice.ephemeral_secret.diffie_hellman(&bob.signed_prekey_public);
    let dh4 = alice.ephemeral_secret.diffie_hellman(&bob.one_time_prekey_public);

    let padding = [0xFF; 32];
    let key_material_alice = [padding.as_slice(), dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), dh4.as_bytes()].concat();

    Ok(key_material_alice)
}

fn bob_shared_secret(bob: &Bob, alice: &Alice) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let dh1 = bob.signed_prekey_secret.diffie_hellman(&alice.static_id_public);
    let dh2 = bob.static_id_secret.diffie_hellman(&alice.ephemeral_public);
    let dh3 = bob.signed_prekey_secret.diffie_hellman(&alice.ephemeral_public);
    let dh4 = bob.one_time_prekey_secret.diffie_hellman(&alice.ephemeral_public);

    let padding = [0xFF; 32];
    let key_material_bob = [padding.as_slice(), dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), dh4.as_bytes()].concat();

    Ok(key_material_bob)
}

fn init_bob() -> Bob {
    let (identity_secret, identity_public) = generate_keys::generate_identity_keys();
    let (signed_prekey_secret, signed_prekey_public, prekey_signature) = generate_keys::generate_signed_prekey(&identity_secret);
    let one_time_prekeys = generate_keys::generate_onetime_prekeys(1);

    let signed_prekey_bundle = key_structs::SignedPrekeyBundle {
        signed_prekey: signed_prekey_public,
        prekey_signature: prekey_signature,
    };

    let static_id_secret = StaticSecret::from(identity_secret.to_scalar_bytes());
    let static_id_public = PublicKey::from(identity_public.to_montgomery().to_bytes());

    return Bob {
        identity_secret,
        identity_public,
        static_id_secret,
        static_id_public,
        signed_prekey_secret,
        signed_prekey_public,
        signature: prekey_signature,
        one_time_prekey_secret: one_time_prekeys[0].1.clone(), //just use the first one for testing
        one_time_prekey_public: one_time_prekeys[0].2.clone(),
    }
}

fn init_alice() -> Alice {
    let (identity_secret, identity_public) = generate_keys::generate_identity_keys();
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let static_id_secret = StaticSecret::from(identity_secret.to_scalar_bytes());
    let static_id_public = PublicKey::from(identity_public.to_montgomery().to_bytes());


    return Alice {
        identity_secret,
        identity_public,
        static_id_secret,
        static_id_public,
        ephemeral_secret,
        ephemeral_public,
    }
}

fn verify_prekey_signature(identity_public: &VerifyingKey, signed_prekey_public: &PublicKey, signature: &Signature) -> bool {
    return identity_public.verify(signed_prekey_public.as_bytes(), signature).is_ok();
}