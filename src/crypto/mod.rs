use base64::decode;
use openpgp::crypto::mpi::Ciphertext;
use std::io::Cursor;
use std::string;

use openpgp::cert::prelude::*;
use openpgp::crypto::{KeyPair, SessionKey};
use openpgp::packet::key::SecretParts;
use openpgp::packet::key::UnspecifiedRole;
use openpgp::packet::Key;
use openpgp::parse::{
    stream::{DecryptionHelper, DecryptorBuilder, VerificationHelper},
    Parse,
};
use openpgp::policy::StandardPolicy as P;
use openpgp::policy::{Policy, StandardPolicy};
use openpgp::serialize::stream::*;
use openpgp::types::SymmetricAlgorithm;
use openpgp::Fingerprint;
use openpgp::KeyID;
use sequoia_openpgp as openpgp;
use std::collections::HashMap;
use std::error::Error;
use std::io::{self, Write};
// Ensure Write is imported
pub fn sign_challenge_with_key(
    challenge: &str,
    enc_private_key_base64: &str,
) -> Result<String, Box<dyn Error>> {
    // Decode the base64-encoded private key
    let enc_private_key = decode(enc_private_key_base64)?;

    // Load the private key
    let cert = openpgp::Cert::from_reader(&*enc_private_key)?;

    // Prepare the helper with the private key
    let key_pair = cert
        .keys()
        .unencrypted_secret()
        .with_policy(&P::new(), None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .ok_or("No signing key found")?
        .key()
        .clone()
        .into_keypair()?;

    // Sign the challenge
    let signed_challenge_base64 = sign_message_with_keypair(challenge, key_pair)?;

    Ok(signed_challenge_base64)
}

pub fn sign_message_with_keypair(message: &str, keypair: KeyPair) -> Result<String, String> {
    let mut signed_message = Vec::new();
    let message_writer = Message::new(&mut signed_message);

    let mut signer = Signer::new(message_writer, keypair)
        .detached()
        .build()
        .map_err(|e| e.to_string())?;

    signer
        .write_all(message.as_bytes())
        .map_err(|_| "Failed to write message to signer.")?;
    signer
        .finalize()
        .map_err(|_| "Failed to finalize signer.")?;

    let mut armored_signature = Vec::new();
    let mut armor_writer =
        openpgp::armor::Writer::new(&mut armored_signature, openpgp::armor::Kind::Signature)
            .map_err(|e| e.to_string())?;

    armor_writer
        .write_all(&signed_message)
        .map_err(|_| "Failed to write signature.")?;
    armor_writer
        .finalize()
        .map_err(|_| "Failed to finalize armored writer.")?;

    let base64_encoded_signature = base64::encode(armored_signature);
    Ok(base64_encoded_signature)
}

pub fn get_key_pair(
    private_key_b64: &str,
) -> Result<Key<SecretParts, UnspecifiedRole>, Box<dyn Error>> {
    let private_key_bytes = decode(private_key_b64)?;
    let cert = Cert::from_bytes(&private_key_bytes)?;
    let p = &StandardPolicy::new();

    // Get the secret key from the certificate for encryption without password
    let keypair = cert
        .keys()
        .with_policy(p, None)
        .secret()
        .for_storage_encryption()
        .nth(0)
        .ok_or_else(|| "No suitable key found in Cert.")?
        .key()
        .clone();

    // The keypair now contains the decrypted secret key
    // You can use it to perform cryptographic operations

    Ok(keypair)
}

pub fn decrypt_message(
    sk: &Key<openpgp::packet::key::SecretParts, openpgp::packet::key::UnspecifiedRole>,
    text: &String,
) -> openpgp::Result<String> {
    let p = StandardPolicy::new();
    let ciphertext = decode(text)?;
    let helper = Helper {
        secret: &sk,
        policy: &p,
    };

    // Parse the message and create a decryptor with the helper.
    let mut decryptor = DecryptorBuilder::from_bytes(&ciphertext)?.with_policy(&p, None, helper)?;

    // Read the decrypted data
    let mut plaintext = Cursor::new(Vec::new());

    // Copy the decrypted data to the plaintext Vec<u8>
    std::io::copy(&mut decryptor, &mut plaintext)?;

    // Get the plaintext Vec<u8> from the Cursor
    let plaintext = plaintext.into_inner();
    let plaintext = String::from_utf8(plaintext)?;
    println!("Decrypted message: {}", plaintext);

    Ok(plaintext)
}

struct Helper<'a> {
    secret: &'a Key<openpgp::packet::key::SecretParts, openpgp::packet::key::UnspecifiedRole>,
    policy: &'a dyn Policy,
}

impl<'a> openpgp::parse::stream::DecryptionHelper for Helper<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(openpgp::types::SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool,
    {
        // The secret key is already decrypted.
        let mut pair = KeyPair::from(self.secret.clone().into_keypair()?);

        pkesks[0]
            .decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        Ok(None)
    }
}

impl<'a> VerificationHelper for Helper<'_> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new())
    }

    fn check(
        &mut self,
        structure: openpgp::parse::stream::MessageStructure,
    ) -> openpgp::Result<()> {
        for layer in structure.iter() {
            match layer {
                openpgp::parse::stream::MessageLayer::Compression { algo } => {
                    eprintln!("Compressed using {}", algo)
                }
                openpgp::parse::stream::MessageLayer::Encryption {
                    sym_algo,
                    aead_algo,
                } => {
                    if let Some(aead_algo) = aead_algo {
                        eprintln!("Encrypted and protected using {}/{}", sym_algo, aead_algo);
                    } else {
                        eprintln!("Encrypted using {}", sym_algo);
                    }
                }
                openpgp::parse::stream::MessageLayer::SignatureGroup { ref results } => {
                    for result in results {
                        match result {
                            Ok(openpgp::parse::stream::GoodChecksum { ka, .. }) => {
                                eprintln!("Good signature from {}", ka.cert());
                            }
                            Err(e) => eprintln!("Error: {:?}", e),
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
