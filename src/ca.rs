use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

use ssh_key::{
    Algorithm, Certificate, PrivateKey, PublicKey,
    certificate::{self, CertType},
    rand_core::OsRng,
};

const CERT_VALIDITY_WINDOW_DAYS: u64 = 3; // u64 so it will work in Duration::from_secs

#[derive(Debug)]
pub enum CaError {
    SshKey(ssh_key::Error),
    SystemTime(SystemTimeError),
}

impl From<ssh_key::Error> for CaError {
    fn from(value: ssh_key::Error) -> Self {
        CaError::SshKey(value)
    }
}

impl From<SystemTimeError> for CaError {
    fn from(value: SystemTimeError) -> Self {
        CaError::SystemTime(value)
    }
}

pub fn generate_random_private_key(alg: Algorithm) -> Result<PrivateKey, CaError> {
    Ok(PrivateKey::random(&mut OsRng, alg)?)
}

#[derive(Debug)]
pub struct SshCa {
    private: PrivateKey,
    public: PublicKey,
}

impl SshCa {
    pub fn new(private: PrivateKey, public: PublicKey) -> Self {
        Self { private, public }
    }

    pub fn with_new_keypair(alg: Algorithm) -> Result<Self, CaError> {
        let private = generate_random_private_key(alg)?;
        let public = private.public_key().to_owned();
        Ok(Self { private, public })
    }

    pub fn sign_host_cert(
        &self,
        public: &PublicKey,
        principals: &[&str],
    ) -> Result<Certificate, CaError> {
        self.sign(public, 0, "test-key-id", CertType::Host, principals, "")
    }

    fn sign(
        &self,
        public: &PublicKey,
        serial: u64,
        key_id: &str,
        cert_type: CertType,
        principals: &[&str],
        comment: &str,
    ) -> Result<Certificate, CaError> {
        let valid_after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let valid_before =
            valid_after + Duration::from_secs(CERT_VALIDITY_WINDOW_DAYS * 24 * 60 * 60).as_secs();

        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut OsRng,
            public,
            valid_after,
            valid_before,
        )?;
        builder.serial(serial)?;
        builder.key_id(key_id)?;
        builder.cert_type(cert_type)?;
        builder.comment(comment)?;

        for principal in principals {
            builder.valid_principal(*principal)?;
        }

        let cert = builder.sign(&self.private)?;
        Ok(cert)
    }
}
