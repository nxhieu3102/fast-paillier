/// A wrapper around BigInt that implements Serialize and Deserialize
pub mod serializable_bigint {
    use std::str::FromStr;

    use num_bigint::BigInt;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a BigInt to a string
    pub fn serialize<S>(_value: &BigInt, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&_value.to_str_radix(10))
    }

    /// Deserialize a BigInt from a string
    pub fn deserialize<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BigInt::from_str(&s).map_err(Error::custom)
    }
}

/// Serialize a vector of BigInts to a string
pub mod serializable_vec_bigint {
    use std::str::FromStr;

    use num_bigint::BigInt;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a vector of BigInts to a string
    pub fn serialize<S>(_value: &[BigInt], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(
            &_value
                .iter()
                .map(|x| x.to_str_radix(10))
                .collect::<Vec<String>>()
                .join(","),
        )
    }

    /// Deserialize a vector of BigInts from a string
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<BigInt>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .split(",")
            .map(|x| BigInt::from_str(x).map_err(Error::custom))
            .collect::<Result<Vec<BigInt>, D::Error>>()
    }
}

/// Serialize a array of BigInts to a string
pub mod serializable_array_bigint {
    use std::str::FromStr;

    use num_bigint::BigInt;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a vector of BigInts to a string
    pub fn serialize<S, const N: usize>(
        _value: &[BigInt; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(
            &_value
                .iter()
                .map(|x| x.to_str_radix(10))
                .collect::<Vec<String>>()
                .join(","),
        )
    }

    /// Deserialize a vector of BigInts from a string
    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[BigInt; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let values = s
            .split(",")
            .map(|x| BigInt::from_str(x).map_err(Error::custom))
            .collect::<Result<Vec<BigInt>, D::Error>>()?;
        if values.len() != N {
            return Err(D::Error::custom(format!(
                "Expected array of length {}, got {}",
                N,
                values.len()
            )));
        }
        let mut result = [BigInt::ZERO; N];
        for (i, value) in values.iter().enumerate() {
            result[i] = value.clone();
        }
        Ok(result)
    }
}
