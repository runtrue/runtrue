struct StrictJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with unique object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .map(StrictJsonValue)
                    .ok_or_else(|| E::custom("JSON number must be finite"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJsonValue(serde_json::Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
                    values.push(value.0);
                }
                Ok(StrictJsonValue(serde_json::Value::Array(values)))
            }

            fn visit_map<A>(self, mut mapping: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = mapping.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(A::Error::custom(format!(
                            "duplicate seccomp JSON key `{key}`"
                        )));
                    }
                    values.insert(key, mapping.next_value::<StrictJsonValue>()?.0);
                }
                Ok(StrictJsonValue(serde_json::Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

pub(crate) fn validate_seccomp_profile(path: &Path) -> Result<(), OciError> {
    let bytes = fs::read(path).map_err(|source| io_error("read seccomp profile", path, source))?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|_| OciError::InvalidSeccompProfile("profile is not strict JSON".to_owned()))?
        .0;
    deserializer
        .end()
        .map_err(|_| OciError::InvalidSeccompProfile("profile has trailing data".to_owned()))?;
    let object = value.as_object().ok_or_else(|| {
        OciError::InvalidSeccompProfile("profile root must be an object".to_owned())
    })?;
    let default_action = object
        .get("defaultAction")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            OciError::InvalidSeccompProfile(
                "profile must declare a deny-by-default action".to_owned(),
            )
        })?;
    if !matches!(
        default_action,
        "SCMP_ACT_ERRNO" | "SCMP_ACT_KILL" | "SCMP_ACT_KILL_PROCESS" | "SCMP_ACT_TRAP"
    ) || object.contains_key("listenerPath")
        || object.contains_key("listenerMetadata")
    {
        return Err(OciError::InvalidSeccompProfile(
            "profile must deny by default and cannot delegate seccomp notifications".to_owned(),
        ));
    }
    Ok(())
}
use crate::{
    fmt, fs, io_error, Deserialize, Deserializer, MapAccess, OciError, Path, SeqAccess, Visitor,
};
use serde::de::Error as _;
