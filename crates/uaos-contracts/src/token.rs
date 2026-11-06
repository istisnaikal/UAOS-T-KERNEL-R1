// SPDX-License-Identifier: Apache-2.0

//! Shared serde and JSON Schema support for validated string newtypes.

/// Implements `Serialize`, `Deserialize` (through the type's validating `new`) and `JsonSchema`
/// (a string with `pattern`) for a newtype `$name(String)`. The call site must have `Cow`,
/// `Serialize`, `Serializer`, `Deserialize`, `Deserializer`, `JsonSchema`, `Schema`,
/// `SchemaGenerator` and `json_schema` in scope.
macro_rules! string_token_serde {
    ($name:ident, $pattern:literal) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({ "type": "string", "pattern": $pattern })
            }
        }
    };
}

pub(crate) use string_token_serde;
