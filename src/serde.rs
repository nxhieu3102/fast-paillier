// TODO: update this to use the new API

use rug::Integer;

use crate::{DecryptionKey, EncryptionKey};

impl serde::Serialize for EncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (self.n_size, self.a_size, self.h.clone(), self.n.clone()).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let (n_size, a_size, h, n) = <(u32, u32, Integer, Integer)>::deserialize(deserializer)?;
        Ok(EncryptionKey::new(n_size, a_size, h, n).map_err(|_| {
            <D::Error as serde::de::Error>::custom("invalid paillier encryption key")
        })?)
    }
}

impl serde::Serialize for DecryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        [self.n_size(), self.a_size()].serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DecryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let [n_size, a_size] = <[u32; 2]>::deserialize(deserializer)?;
        DecryptionKey::generate(n_size, a_size)
            .map_err(|_| <D::Error as serde::de::Error>::custom("invalid paillier decryption key"))
    }
}
