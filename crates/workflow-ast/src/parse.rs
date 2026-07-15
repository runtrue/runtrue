use crate::{ParseError, Workflow};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use std::{cell::Cell, fmt};

pub fn parse_yaml(source: &str) -> Result<Workflow, ParseError> {
    if source.len() > 1024 * 1024 {
        return Err(ParseError::TooLarge);
    }
    validate_expanded_yaml_budget(source)?;
    let workflow: Workflow = serde_yaml::from_str(source)?;
    if workflow.version != 1 {
        return Err(ParseError::UnsupportedVersion(workflow.version));
    }
    Ok(workflow)
}

const MAX_EXPANDED_YAML_NODES: usize = 100_000;
const MAX_EXPANDED_YAML_SCALAR_BYTES: usize = 8 * 1024 * 1024;

/// Walk the deserializer before allocating the typed AST. Serde YAML aliases
/// replay anchored events, so the source-size limit alone does not bound the
/// amount of expanded data. This seed counts the replayed representation and
/// aborts before a small alias-heavy document can allocate an enormous AST.
fn validate_expanded_yaml_budget(source: &str) -> Result<(), serde_yaml::Error> {
    let budget = ExpandedYamlBudget::default();
    for document in serde_yaml::Deserializer::from_str(source) {
        ExpandedYamlSeed { budget: &budget }.deserialize(document)?;
    }
    Ok(())
}

#[derive(Default)]
struct ExpandedYamlBudget {
    nodes: Cell<usize>,
    scalar_bytes: Cell<usize>,
}

impl ExpandedYamlBudget {
    fn add_node<E: serde::de::Error>(&self) -> Result<(), E> {
        let nodes = self.nodes.get().saturating_add(1);
        if nodes > MAX_EXPANDED_YAML_NODES {
            return Err(E::custom(format!(
                "expanded YAML exceeds the {MAX_EXPANDED_YAML_NODES}-node limit"
            )));
        }
        self.nodes.set(nodes);
        Ok(())
    }

    fn add_scalar_bytes<E: serde::de::Error>(&self, bytes: usize) -> Result<(), E> {
        let scalar_bytes = self.scalar_bytes.get().saturating_add(bytes);
        if scalar_bytes > MAX_EXPANDED_YAML_SCALAR_BYTES {
            return Err(E::custom(format!(
                "expanded YAML exceeds the {MAX_EXPANDED_YAML_SCALAR_BYTES}-byte scalar limit"
            )));
        }
        self.scalar_bytes.set(scalar_bytes);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ExpandedYamlSeed<'a> {
    budget: &'a ExpandedYamlBudget,
}

impl<'de> DeserializeSeed<'de> for ExpandedYamlSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.budget.add_node()?;
        deserializer.deserialize_any(ExpandedYamlVisitor {
            budget: self.budget,
        })
    }
}

struct ExpandedYamlVisitor<'a> {
    budget: &'a ExpandedYamlBudget,
}

impl<'de> Visitor<'de> for ExpandedYamlVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("YAML within the expanded-data budget")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.budget.add_scalar_bytes(value.len())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.budget.add_scalar_bytes(value.len())
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.budget.add_scalar_bytes(value.len())
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.budget.add_scalar_bytes(value.len())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        ExpandedYamlSeed {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        ExpandedYamlSeed {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(ExpandedYamlSeed {
                budget: self.budget,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut mapping: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while mapping
            .next_key_seed(ExpandedYamlSeed {
                budget: self.budget,
            })?
            .is_some()
        {
            mapping.next_value_seed(ExpandedYamlSeed {
                budget: self.budget,
            })?;
        }
        Ok(())
    }
}
