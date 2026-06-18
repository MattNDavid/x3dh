use x25519_dalek::{PublicKey};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

pub struct InitX3dhKeys {
    pub identity_key: SigningKey, //permanent
    pub ephemeral_key: SigningKey, //rotates periodically
}

pub struct RecvX3dhKeys {
    pub identity_key: VerifyingKey, //permanent
    pub signed_prekey: PublicKey, //rotates periodically
    pub one_time_prekey: PublicKey, //one time use
}

pub struct PublishInitialKeys {
    pub identity_key: VerifyingKey, //permanent
    pub signed_prekey: PublicKey, //rotates periodically
    pub prekey_signature: Signature, //signature of signed prekey with identity key
    pub one_time_prekey: Vec<PublicKey>, //one time use
}

pub struct SignedPrekeyBundle {
    pub signed_prekey: PublicKey, //rotates periodically
    pub prekey_signature: Signature, //signature of signed prekey with identity key
}
