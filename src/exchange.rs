use crate::generate_keys;
use crate::key_structs;
use x25519_dalek::PublicKey;
use ed25519_dalek::VerifyingKey;

pub fn publish_initial_bundle(identity_key: VerifyingKey, signed_prekey: key_structs::SignedPrekeyBundle, one_time_prekeys: Vec<PublicKey>) -> key_structs::PublishInitialKeys {

    return key_structs::PublishInitialKeys {
        identity_key: identity_key,
        signed_prekey: signed_prekey.signed_prekey,
        prekey_signature: signed_prekey.prekey_signature,
        one_time_prekey: one_time_prekeys,
    }

}
