use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use rand::rngs::OsRng;

#[allow(dead_code)]
pub struct Identity {
    pub signing_key: SigningKey,
}

impl Identity {
    pub fn load_or_generate<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        if path.as_ref().exists() {
            let mut file = File::open(path).map_err(|e| format!("Failed to open key file: {}", e))?;
            let mut bytes = [0u8; 32];
            file.read_exact(&mut bytes).map_err(|e| format!("Failed to read key file: {}", e))?;
            let signing_key = SigningKey::from_bytes(&bytes);
            Ok(Identity { signing_key })
        } else {
            let signing_key = SigningKey::generate(&mut OsRng);
            let mut file = File::create(path).map_err(|e| format!("Failed to create key file: {}", e))?;
            // set permissions to 600 on unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = file.metadata() {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o600);
                    let _ = file.set_permissions(perms);
                }
            }
            file.write_all(&signing_key.to_bytes()).map_err(|e| format!("Failed to write key file: {}", e))?;
            Ok(Identity { signing_key })
        }
    }

    #[allow(dead_code)]
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    #[allow(dead_code)]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

pub fn verify_signature(pubkey_bytes: &[u8; 32], message: &[u8], signature_bytes: &[u8; 64]) -> bool {
    if let Ok(verifying_key) = VerifyingKey::from_bytes(pubkey_bytes) {
        let sig = Signature::from_bytes(signature_bytes);
        return verifying_key.verify(message, &sig).is_ok();
    }
    false
}
