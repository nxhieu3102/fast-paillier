use core::fmt;

// cargo build --features="serde"
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::EncryptionKey;

impl Serialize for EncryptionKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("EncryptionKey", 9)?;
        s.serialize_field("n_size", &self.n_size())?;
        s.serialize_field("a_size", &self.a_size())?;
        s.serialize_field("nounce_size", &self.nounce_size())?;
        s.serialize_field("h", &self.h().to_string())?;
        s.serialize_field("n", &self.n().to_string())?;
        s.serialize_field("nn", &self.nn().to_string())?;
        s.serialize_field("h_pow_n", &self.h_pow_n().to_string())?;
        s.serialize_field("half_n", &self.half_n().to_string())?;
        s.serialize_field("neg_half_n", &self.neg_half_n().to_string())?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for EncryptionKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EncryptionKeyVisitor;

        impl<'de> Visitor<'de> for EncryptionKeyVisitor {
            type Value = EncryptionKey;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "struct EncryptionKey")
            }

            fn visit_map<V: MapAccess<'de>>(self, mut map: V) -> Result<Self::Value, V::Error> {
                let mut n_size = None;
                let mut a_size = None;
                let mut nounce_size = None;
                let mut h = None;
                let mut n = None;
                let mut nn = None;
                let mut h_pow_n = None;
                let mut half_n = None;
                let mut neg_half_n = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "n_size" => n_size = Some(map.next_value()?),
                        "a_size" => a_size = Some(map.next_value()?),
                        "nounce_size" => nounce_size = Some(map.next_value()?),
                        "h" => {
                            h = Some(
                                Integer::parse(&map.next_value::<String>()?)
                                    .map_err(DeError::custom)?,
                            )
                        }
                        "n" => {
                            n = Some(
                                Integer::parse(&map.next_value::<String>()?)
                                    .map_err(DeError::custom)?,
                            )
                        }
                        "nn" => {
                            nn = Some(
                                Integer::parse(&map.next_value::<String>()?)
                                    .map_err(DeError::custom)?,
                            )
                        }
                        "h_pow_n" => {
                            h_pow_n = Some(
                                Integer::parse(&map.next_value::<String>()?)
                                    .map_err(DeError::custom)?,
                            )
                        }
                        "half_n" => {
                            half_n = Some(
                                Integer::parse(&map.next_value::<String>()?)
                                    .map_err(DeError::custom)?,
                            )
                        }
                        "neg_half_n" => {
                            neg_half_n = Some(
                                Integer::parse(&map.next_value::<String>()?)
                                    .map_err(DeError::custom)?,
                            )
                        }
                        _ => {
                            return Err(DeError::unknown_field(
                                &key,
                                &[
                                    "n_size",
                                    "a_size",
                                    "nounce_size",
                                    "h",
                                    "n",
                                    "nn",
                                    "h_pow_n",
                                    "half_n",
                                    "neg_half_n",
                                ],
                            ))
                        }
                    }
                }

                Ok(EncryptionKey {
                    n_size: n_size.ok_or_else(|| DeError::missing_field("n_size"))?,
                    a_size: a_size.ok_or_else(|| DeError::missing_field("a_size"))?,
                    nounce_size: nounce_size
                        .ok_or_else(|| DeError::missing_field("nounce_size"))?,
                    h: h.ok_or_else(|| DeError::missing_field("h"))?,
                    n: n.ok_or_else(|| DeError::missing_field("n"))?,
                    nn: nn.ok_or_else(|| DeError::missing_field("nn"))?,
                    h_pow_n: h_pow_n.ok_or_else(|| DeError::missing_field("h_pow_n"))?,
                    half_n: half_n.ok_or_else(|| DeError::missing_field("half_n"))?,
                    neg_half_n: neg_half_n.ok_or_else(|| DeError::missing_field("neg_half_n"))?,
                })
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Bool(v),
                    &self,
                ))
            }

            fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(v as i64)
            }

            fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(v as i64)
            }

            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i64(v as i64)
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Signed(v),
                    &self,
                ))
            }

            fn visit_i128<E>(self, v: i128) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut buf = [0u8; 58];
                let mut writer = serde::format::Buf::new(&mut buf);
                std::fmt::Write::write_fmt(&mut writer, format_args!("integer `{}` as i128", v))
                    .unwrap();
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Other(writer.as_str()),
                    &self,
                ))
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_u64(v as u64)
            }

            fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_u64(v as u64)
            }

            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_u64(v as u64)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Unsigned(v),
                    &self,
                ))
            }

            fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut buf = [0u8; 57];
                let mut writer = serde::format::Buf::new(&mut buf);
                std::fmt::Write::write_fmt(&mut writer, format_args!("integer `{}` as u128", v))
                    .unwrap();
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Other(writer.as_str()),
                    &self,
                ))
            }

            fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_f64(v as f64)
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Float(v),
                    &self,
                ))
            }

            fn visit_char<E>(self, v: char) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v.encode_utf8(&mut [0u8; 4]))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Str(v),
                    &self,
                ))
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Bytes(v),
                    &self,
                ))
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(v)
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(&v)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Option,
                    &self,
                ))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let _ = deserializer;
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Option,
                    &self,
                ))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Unit,
                    &self,
                ))
            }

            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                let _ = deserializer;
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::NewtypeStruct,
                    &self,
                ))
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let _ = seq;
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Seq,
                    &self,
                ))
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::EnumAccess<'de>,
            {
                let _ = data;
                Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Enum,
                    &self,
                ))
            }
        }

        deserializer.deserialize_struct(
            "EncryptionKey",
            &[
                "n_size",
                "a_size",
                "nounce_size",
                "h",
                "n",
                "nn",
                "h_pow_n",
                "half_n",
                "neg_half_n",
            ],
            EncryptionKeyVisitor,
        )
    }
}

impl Serialize for DecryptionKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("DecryptionKey", 4)?;
        s.serialize_field("ek", &self.ek)?;
        s.serialize_field("p", &self.p.to_string())?;
        s.serialize_field("q", &self.q.to_string())?;
        s.serialize_field("alpha", &self.alpha.to_string())?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for DecryptionKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DecryptionKeyVisitor;

        impl<'de> Visitor<'de> for DecryptionKeyVisitor {
            type Value = DecryptionKey;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "struct DecryptionKey")
            }

            fn visit_map<V: MapAccess<'de>>(mut map: V) -> Result<Self::Value, V::Error> {
                let mut ek = None;
                let mut p = None;
                let mut q = None;
                let mut alpha = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "ek" => ek = Some(map.next_value()?),
                        "p" => {
                            p = Some(
                                Integer::parse(&map.next_value::<String>()?)
                                    .map_err(DeError::custom)?,
                            )
                        }
                        "q" => {
                            q = Some(
                                Integer::parse(&map.next_value::<String>()?)
                                    .map_err(DeError::custom)?,
                            )
                        }
                        "alpha" => {
                            alpha = Some(
                                Integer::parse(&map.next_value::<String>()?)
                                    .map_err(DeError::custom)?,
                            )
                        }
                        _ => return Err(DeError::unknown_field(&key, &["ek", "p", "q", "alpha"])),
                    }
                }

                Ok(DecryptionKey {
                    ek: ek.ok_or_else(|| DeError::missing_field("ek"))?,
                    p: p.ok_or_else(|| DeError::missing_field("p"))?,
                    q: q.ok_or_else(|| DeError::missing_field("q"))?,
                    alpha: alpha.ok_or_else(|| DeError::missing_field("alpha"))?,
                })
            }
        }

        deserializer.deserialize_struct(
            "DecryptionKey",
            &["ek", "p", "q", "alpha"],
            DecryptionKeyVisitor,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rug::Integer;
    use serde_json;

    #[test]
    fn test_manual_serde_decryption_key() {
        // Create dummy EncryptionKey
        let ek = EncryptionKey {
            n_size: 2048,
            a_size: 512,
            nounce_size: 256,
            h: Integer::from(123),
            n: Integer::from(456),
            nn: Integer::from(456 * 456),
            h_pow_n: Integer::from(789),
            half_n: Integer::from(228),
            neg_half_n: Integer::from(-228),
        };

        // Create dummy DecryptionKey
        let dk = DecryptionKey {
            ek,
            p: Integer::from(11),
            q: Integer::from(13),
            alpha: Integer::from(7),
        };

        // Serialize to JSON
        let serialized = serde_json::to_string_pretty(&dk).expect("Failed to serialize");
        println!("Serialized JSON:\n{serialized}");

        // Deserialize back
        let deserialized: DecryptionKey =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // You can’t do assert_eq! directly because Integer doesn’t derive PartialEq,
        // so do manual comparison
        assert_eq!(dk.p, deserialized.p);
        assert_eq!(dk.q, deserialized.q);
        assert_eq!(dk.alpha, deserialized.alpha);

        assert_eq!(dk.ek.n_size, deserialized.ek.n_size);
        assert_eq!(dk.ek.a_size, deserialized.ek.a_size);
        assert_eq!(dk.ek.nounce_size, deserialized.ek.nounce_size);
        assert_eq!(dk.ek.h, deserialized.ek.h);
        assert_eq!(dk.ek.n, deserialized.ek.n);
        assert_eq!(dk.ek.nn, deserialized.ek.nn);
        assert_eq!(dk.ek.h_pow_n, deserialized.ek.h_pow_n);
        assert_eq!(dk.ek.half_n, deserialized.ek.half_n);
        assert_eq!(dk.ek.neg_half_n, deserialized.ek.neg_half_n);
    }
}
