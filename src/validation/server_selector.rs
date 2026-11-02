use std::{collections::BTreeMap, str::FromStr};

use kube::core::{Expression, Selector, SelectorExt};
use serde::{Deserialize, Serialize};

use super::primitives::{label_component, label_key};

/// A validated Kubernetes label selector, persisted as its canonical string.
/// Empty annotations are rejected so an accidental empty value cannot select all.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServerSelector(Selector);

impl ServerSelector {
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.0.matches(labels)
    }
}

impl FromStr for ServerSelector {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || "expected a nonempty Kubernetes label selector".to_owned();
        let mut depth = 0;
        let mut start = 0;
        let mut expressions = Vec::new();

        // Commas inside a set separate values; only outer commas join requirements.
        for (index, character) in value.char_indices() {
            match character {
                '(' if depth == 0 => depth = 1,
                ')' if depth == 1 => depth = 0,
                '(' | ')' => return Err(invalid()),
                ',' if depth == 0 => {
                    expressions.push(parse_requirement(&value[start..index]).ok_or_else(invalid)?);
                    start = index + 1;
                }
                _ => {}
            }
        }

        if depth != 0 {
            return Err(invalid());
        }

        expressions.push(parse_requirement(&value[start..]).ok_or_else(invalid)?);

        Ok(Self(expressions.into_iter().collect()))
    }
}

impl TryFrom<String> for ServerSelector {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<ServerSelector> for String {
    fn from(value: ServerSelector) -> Self {
        value.0.to_string()
    }
}

fn parse_requirement(value: &str) -> Option<Expression> {
    let value = value.trim_matches(|c: char| c.is_ascii_whitespace());

    if let Some(key) = value.strip_prefix('!') {
        let key = key.trim_matches(|c: char| c.is_ascii_whitespace());

        return label_key(key).then(|| Expression::DoesNotExist(key.into()));
    }

    let end = value
        .find(|c: char| c.is_ascii_whitespace() || matches!(c, '=' | '!' | '(' | ')'))
        .unwrap_or(value.len());
    let key = &value[..end];

    if !label_key(key) {
        return None;
    }

    let rest = value[end..].trim_matches(|c: char| c.is_ascii_whitespace());

    if rest.is_empty() {
        return Some(Expression::Exists(key.into()));
    }

    for operator in ["!=", "==", "="] {
        if let Some(value) = rest.strip_prefix(operator) {
            let value = value.trim_matches(|c: char| c.is_ascii_whitespace());

            if !label_component(value, true) {
                return None;
            }

            return Some(if operator == "!=" {
                Expression::NotEqual(key.into(), value.into())
            } else {
                Expression::Equal(key.into(), value.into())
            });
        }
    }

    for operator in ["in", "notin"] {
        if let Some(values) = rest.strip_prefix(operator) {
            let values = values
                .trim_matches(|c: char| c.is_ascii_whitespace())
                .strip_prefix('(')?
                .strip_suffix(')')?;
            let values = values
                .split(',')
                .map(|value| value.trim_matches(|c: char| c.is_ascii_whitespace()))
                .map(|value| label_component(value, true).then(|| value.to_owned()))
                .collect::<Option<_>>()?;

            return Some(if operator == "in" {
                Expression::In(key.into(), values)
            } else {
                Expression::NotIn(key.into(), values)
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kubernetes_operators_match_labels_including_missing_and_empty_values() {
        let labels = BTreeMap::from([
            ("region".into(), "europe".into()),
            ("empty".into(), "".into()),
        ]);

        for (value, expected) in [
            ("region=europe", true),
            ("region == europe", true),
            ("region!=russia", true),
            ("region in (europe, russia)", true),
            ("region notin (russia)", true),
            ("region", true),
            ("!zone", true),
            ("zone!=a", true),
            ("zone notin (a)", true),
            ("empty=", true),
            ("empty in ()", true),
            ("region=europe,!zone,empty=", true),
            ("region=russia", false),
            ("region notin (europe,russia)", false),
            ("zone in (a)", false),
            ("zone=", false),
            ("!empty", false),
            ("region=europe,region=russia", false),
        ] {
            let selector: ServerSelector = value.parse().unwrap();

            assert_eq!(selector.matches(&labels), expected, "{value}");

            let persisted = serde_json::to_value(&selector).unwrap();
            let restored: ServerSelector = serde_json::from_value(persisted).unwrap();

            assert_eq!(restored, selector);
        }
    }
}
