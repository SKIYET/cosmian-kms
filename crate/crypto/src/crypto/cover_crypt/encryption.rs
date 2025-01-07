use cloudproof::reexport::crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    reexport::zeroize::Zeroizing,
};
use cosmian_cover_crypt::{
    api::Covercrypt,
    traits::{PkeAc, AE},
    AccessPolicy, EncryptedHeader, MasterPublicKey,
};
use cosmian_kmip::{
    kmip_2_1::{
        kmip_objects::Object,
        kmip_operations::{Encrypt, EncryptResponse},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
    },
    DataToEncrypt,
};
use tracing::{debug, trace};

use crate::{crypto::EncryptionSystem, error::CryptoError};

/// Encrypt a single block of data using an hybrid encryption mode
/// Cannot be used as a stream cipher
pub struct CoverCryptEncryption {
    cover_crypt: Covercrypt,
    public_key_uid: String,
    public_key_bytes: Zeroizing<Vec<u8>>,
}

impl CoverCryptEncryption {
    pub fn instantiate(
        cover_crypt: Covercrypt,
        public_key_uid: &str,
        public_key: &Object,
    ) -> Result<Self, CryptoError> {
        let (public_key_bytes, _public_key_attributes) =
            public_key.key_block()?.key_bytes_and_attributes()?;

        trace!("Instantiated hybrid CoverCrypt encrypt for public key id: {public_key_uid}");

        Ok(Self {
            cover_crypt,
            public_key_uid: public_key_uid.into(),
            public_key_bytes,
        })
    }

    /// Encrypt multiple LEB128-serialized payloads
    ///
    /// The input plaintext data is serialized using LEB128 (bulk mode).
    /// Each chunk of data is encrypted and serialized back to LEB128.
    ///
    /// Bulk encryption / decryption scheme
    ///
    /// ENC request
    /// | `nb_chunks` (LEB128) | `chunk_size` (LEB128) | `chunk_data` (plaintext)
    ///                           <-------------- `nb_chunks` times ------------>
    ///
    /// ENC response
    /// | EH | `nb_chunks` (LEB128) | `chunk_size` (LEB128) | `chunk_data` (encrypted)
    ///                                <-------------- `nb_chunks` times ------------>
    ///
    /// DEC request
    /// | `nb_chunks` (LEB128) | size(EH + `chunk_data`) (LEB128) | EH | `chunk_data` (encrypted)
    ///                                                             <------ chunk with EH ------>
    ///                          <------------------------ `nb_chunks` times ------------------->
    ///
    /// DEC response
    /// | `nb_chunks` (LEB128) | `chunk_size` (LEB128) | `chunk_data` (plaintext)
    ///                           <------------- `nb_chunks` times ------------->
    ///
    fn bulk_encrypt<
        const KEY_LENGTH: usize,
        E: AE<KEY_LENGTH, Error = cosmian_cover_crypt::Error>,
    >(
        &self,
        encrypted_header: &[u8],
        plaintext: &[u8],
        access_policy: &AccessPolicy,
        mpk: &MasterPublicKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut de = Deserializer::new(plaintext);
        let mut ser = Serializer::new();

        // number of chunks of plaintext data to encrypt
        let nb_chunks = {
            let len = de.read_leb128_u64()?;
            ser.write_leb128_u64(len)?;
            usize::try_from(len).map_err(|e| {
                CryptoError::Kmip(format!(
                    "size of vector is too big for architecture: {len} bytes. Error: {e:?}"
                ))
            })?
        };

        // encrypt each chunk and serialize it
        // a copy of the encrypted header is also serialized, prepending the chunk
        for _ in 0..nb_chunks {
            let chunk_data = de.read_vec_as_ref()?;
            let mut encrypted_block =
                self.encrypt::<KEY_LENGTH, E>(chunk_data, mpk, access_policy)?;
            let mut chunk = encrypted_header.to_vec();
            chunk.append(&mut encrypted_block);
            ser.write_vec(&chunk)?;
        }

        Ok(ser.finalize().to_vec())
    }

    fn encrypt<const KEY_LENGTH: usize, E: AE<KEY_LENGTH, Error = cosmian_cover_crypt::Error>>(
        &self,
        plaintext: &[u8],
        mpk: &MasterPublicKey,
        access_policy: &AccessPolicy,
    ) -> Result<Vec<u8>, CryptoError> {
        // Encrypt the data
        let (_encapsulation, encrypted_block) = <cosmian_cover_crypt::api::Covercrypt as PkeAc<
            KEY_LENGTH,
            E,
        >>::encrypt(
            &self.cover_crypt, mpk, access_policy, plaintext
        )
        .map_err(|e| CryptoError::Kmip(e.to_string()))?;

        debug!(
            "Encrypted data with public key {} of len (CT/Enc): {}/{}",
            self.public_key_uid,
            plaintext.len(),
            encrypted_block.len(),
        );

        Ok(encrypted_block)
    }
}

impl EncryptionSystem for CoverCryptEncryption {
    fn encrypt<const KEY_LENGTH: usize, E: AE<KEY_LENGTH, Error = cosmian_cover_crypt::Error>>(
        &self,
        request: &Encrypt,
    ) -> Result<EncryptResponse, CryptoError> {
        let authenticated_encryption_additional_data =
            request.authenticated_encryption_additional_data.as_deref();

        let data_to_encrypt = DataToEncrypt::try_from_bytes(
            request
                .data
                .as_deref()
                .ok_or_else(|| CryptoError::Kmip("Missing data to encrypt".to_owned()))?,
        )?;

        let public_key =
            MasterPublicKey::deserialize(self.public_key_bytes.as_slice()).map_err(|e| {
                CryptoError::Kmip(format!(
                    "cover crypt encipher: failed recovering the public key: {e}"
                ))
            })?;

        let encryption_policy_string = data_to_encrypt
            .encryption_policy
            .as_deref()
            .ok_or_else(|| CryptoError::Kmip("encryption policy missing".to_owned()))?;
        let encryption_policy = AccessPolicy::parse(encryption_policy_string)
            .map_err(|e| CryptoError::Kmip(format!("invalid encryption policy: {e}")))?;

        // Generate a symmetric key and encrypt the header
        let (_symmetric_key, encrypted_header) = EncryptedHeader::generate(
            &self.cover_crypt,
            &public_key,
            &encryption_policy,
            data_to_encrypt.header_metadata.as_deref(),
            authenticated_encryption_additional_data,
        )
        .map_err(|e| CryptoError::Kmip(e.to_string()))?;

        let mut encrypted_header = encrypted_header
            .serialize()
            .map_err(|e| CryptoError::Kmip(e.to_string()))?;

        let encrypted_data = if let Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCryptBulk),
            ..
        }) = request.cryptographic_parameters
        {
            self.bulk_encrypt::<KEY_LENGTH, E>(
                &encrypted_header,
                &data_to_encrypt.plaintext,
                &encryption_policy,
                &public_key,
            )?
        } else {
            let mut encrypted_data = self.encrypt::<KEY_LENGTH, E>(
                &data_to_encrypt.plaintext,
                &public_key,
                &encryption_policy,
            )?;
            encrypted_header.append(&mut encrypted_data);
            encrypted_header.to_vec()
        };

        Ok(EncryptResponse {
            unique_identifier: UniqueIdentifier::TextString(self.public_key_uid.clone()),
            data: Some(encrypted_data),
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: authenticated_encryption_additional_data
                .map(<[u8]>::to_vec),
        })
    }
}
