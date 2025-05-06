use rug::Integer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use std::fmt;
#[cfg(feature = "serde")]
use serde_json;

use crate::{DecryptionKey, EncryptionKey, Error, Reason, Bug};

// Serializable representation of EncryptionKey
#[derive(Serialize, Deserialize)]
struct SerializableEncryptionKey {
    n_size: u32,
    a_size: u32,
    nounce_size: u32,
    h: String,
    n: String,
    nn: String,
    h_pow_n: String,
    half_n: String,
    neg_half_n: String,
}

// Serializable representation of DecryptionKey
#[derive(Serialize, Deserialize)]
struct SerializableDecryptionKey {
    ek: SerializableEncryptionKey,
    p: String,
    q: String,
    alpha: String,
}

// Convert Integer to hex string
fn integer_to_hex(value: &Integer) -> String {
    format!("{:x}", value)
}

// Convert hex string to Integer
fn hex_to_integer(hex: &str) -> Result<Integer, Error> {
    Integer::from_str_radix(hex, 16)
        .map_err(|_| Error::from(Reason::Ops))
}

impl Serialize for EncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serializable = SerializableEncryptionKey {
            n_size: self.n_size(),
            a_size: self.a_size(),
            nounce_size: self.nounce_size(),
            h: integer_to_hex(self.h()),
            n: integer_to_hex(self.n()),
            nn: integer_to_hex(self.nn()),
            h_pow_n: integer_to_hex(self.h_pow_n()),
            half_n: integer_to_hex(self.half_n()),
            neg_half_n: integer_to_hex(self.neg_half_n()),
        };
        
        serializable.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serializable = SerializableEncryptionKey::deserialize(deserializer)?;
        
        let h = hex_to_integer(&serializable.h).map_err(de::Error::custom)?;
        let n = hex_to_integer(&serializable.n).map_err(de::Error::custom)?;
        
        EncryptionKey::new(
            serializable.n_size,
            serializable.a_size,
            h,
            n,
        )
        .map_err(de::Error::custom)
    }
}

impl Serialize for DecryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serializable = SerializableDecryptionKey {
            ek: SerializableEncryptionKey {
                n_size: self.encryption_key().n_size(),
                a_size: self.encryption_key().a_size(),
                nounce_size: self.encryption_key().nounce_size(),
                h: integer_to_hex(self.encryption_key().h()),
                n: integer_to_hex(self.encryption_key().n()),
                nn: integer_to_hex(self.encryption_key().nn()),
                h_pow_n: integer_to_hex(self.encryption_key().h_pow_n()),
                half_n: integer_to_hex(self.encryption_key().half_n()),
                neg_half_n: integer_to_hex(self.encryption_key().neg_half_n()),
            },
            p: integer_to_hex(self.p()),
            q: integer_to_hex(self.q()),
            alpha: integer_to_hex(self.alpha()),
        };
        
        serializable.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DecryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serializable = SerializableDecryptionKey::deserialize(deserializer)?;
        
        let h = hex_to_integer(&serializable.ek.h).map_err(de::Error::custom)?;
        let n = hex_to_integer(&serializable.ek.n).map_err(de::Error::custom)?;
        
        let ek = EncryptionKey::new(
            serializable.ek.n_size,
            serializable.ek.a_size,
            h,
            n,
        )
        .map_err(de::Error::custom)?;
        
        let p = hex_to_integer(&serializable.p).map_err(de::Error::custom)?;
        let q = hex_to_integer(&serializable.q).map_err(de::Error::custom)?;
        let alpha = hex_to_integer(&serializable.alpha).map_err(de::Error::custom)?;
        
        DecryptionKey::new(ek, p, q, alpha).map_err(de::Error::custom)
    }
}

// Helper methods for easy conversion to/from JSON strings
#[cfg(feature = "serde")]
impl EncryptionKey {
    /// Serialize the EncryptionKey to a JSON string
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self)
            .map_err(|_| Error::from(Reason::Ops))
    }

    /// Deserialize an EncryptionKey from a JSON string
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json)
            .map_err(|_| Error::from(Reason::Ops))
    }
}

#[cfg(feature = "serde")]
impl DecryptionKey {
    /// Serialize the DecryptionKey to a JSON string
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string(self)
            .map_err(|_| Error::from(Reason::Ops))
    }

    /// Deserialize a DecryptionKey from a JSON string
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json)
            .map_err(|_| Error::from(Reason::Ops))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecryptionKey;

    #[test]
    fn test_encryption_key_serialization() {
        // Sample a known key
        let ek = EncryptionKey::sample_112();
        
        // Serialize to JSON string for testing
        let json = ek.to_json().unwrap();
        println!("json: {}", json);
        // Deserialize back
        let deserialized_ek = EncryptionKey::from_json(&json).unwrap();
        
        // Check key properties are preserved
        assert_eq!(ek.n_size(), deserialized_ek.n_size());
        assert_eq!(ek.a_size(), deserialized_ek.a_size());
        assert_eq!(ek.n().to_string(), deserialized_ek.n().to_string());
        assert_eq!(ek.h().to_string(), deserialized_ek.h().to_string());
    }

    #[test]
    fn test_decryption_key_serialization() {
        // Sample a known key
        let dk = DecryptionKey::sample_112();
        
        // Serialize to JSON string for testing
        let json = dk.to_json().unwrap();
        
        // Deserialize back
        let deserialized_dk = DecryptionKey::from_json(&json).unwrap();
        
        // Check key properties are preserved
        assert_eq!(dk.p().to_string(), deserialized_dk.p().to_string());
        assert_eq!(dk.q().to_string(), deserialized_dk.q().to_string());
        assert_eq!(dk.alpha().to_string(), deserialized_dk.alpha().to_string());
        assert_eq!(dk.n().to_string(), deserialized_dk.n().to_string());
    }
}
