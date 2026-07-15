use serde::{
    de::{Error as _, MapAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{collections::BTreeMap, fmt, ops::Deref};

/// A string-keyed deterministic map that rejects duplicate YAML keys.
///
/// Serde's standard map types replace an earlier value when a YAML mapping
/// repeats a key. Workflow configuration must instead fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictMap<V>(BTreeMap<String, V>);

impl<V> Default for StrictMap<V> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<V> From<BTreeMap<String, V>> for StrictMap<V> {
    fn from(values: BTreeMap<String, V>) -> Self {
        Self(values)
    }
}

impl<V> From<StrictMap<V>> for BTreeMap<String, V> {
    fn from(values: StrictMap<V>) -> Self {
        values.0
    }
}

impl<V> Deref for StrictMap<V> {
    type Target = BTreeMap<String, V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, V> IntoIterator for &'a StrictMap<V> {
    type Item = (&'a String, &'a V);
    type IntoIter = std::collections::btree_map::Iter<'a, String, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<V: Serialize> Serialize for StrictMap<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, V> Deserialize<'de> for StrictMap<V>
where
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictMapVisitor<V>(std::marker::PhantomData<V>);

        impl<'de, V> Visitor<'de> for StrictMapVisitor<V>
        where
            V: Deserialize<'de>,
        {
            type Value = StrictMap<V>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a mapping with unique string keys")
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = access.next_entry::<String, V>()? {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(A::Error::custom(format!("duplicate mapping key `{key}`")));
                    }
                }
                Ok(StrictMap(values))
            }
        }

        deserializer.deserialize_map(StrictMapVisitor(std::marker::PhantomData))
    }
}
