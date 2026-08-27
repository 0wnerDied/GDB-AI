use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record", content = "data", rename_all = "snake_case")]
pub enum MiRecord {
    Result {
        token: Option<u64>,
        class: String,
        results: Vec<MiResult>,
    },
    ExecAsync {
        token: Option<u64>,
        class: String,
        results: Vec<MiResult>,
    },
    StatusAsync {
        token: Option<u64>,
        class: String,
        results: Vec<MiResult>,
    },
    NotifyAsync {
        token: Option<u64>,
        class: String,
        results: Vec<MiResult>,
    },
    ConsoleStream(Vec<u8>),
    TargetStream(Vec<u8>),
    LogStream(Vec<u8>),
    Prompt,
}

impl MiRecord {
    pub fn token(&self) -> Option<u64> {
        match self {
            Self::Result { token, .. }
            | Self::ExecAsync { token, .. }
            | Self::StatusAsync { token, .. }
            | Self::NotifyAsync { token, .. } => *token,
            Self::ConsoleStream(_) | Self::TargetStream(_) | Self::LogStream(_) | Self::Prompt => {
                None
            }
        }
    }

    pub fn class(&self) -> Option<&str> {
        match self {
            Self::Result { class, .. }
            | Self::ExecAsync { class, .. }
            | Self::StatusAsync { class, .. }
            | Self::NotifyAsync { class, .. } => Some(class),
            Self::ConsoleStream(_) | Self::TargetStream(_) | Self::LogStream(_) | Self::Prompt => {
                None
            }
        }
    }

    pub fn results(&self) -> &[MiResult] {
        match self {
            Self::Result { results, .. }
            | Self::ExecAsync { results, .. }
            | Self::StatusAsync { results, .. }
            | Self::NotifyAsync { results, .. } => results,
            Self::ConsoleStream(_) | Self::TargetStream(_) | Self::LogStream(_) | Self::Prompt => {
                &[]
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiResult {
    pub name: String,
    pub value: MiValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum MiValue {
    Const(Vec<u8>),
    Tuple(Vec<MiResult>),
    ValueList(Vec<MiValue>),
    ResultList(Vec<MiResult>),
}

impl MiValue {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Const(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()?).ok()
    }

    pub fn results(&self) -> Option<&[MiResult]> {
        match self {
            Self::Tuple(results) | Self::ResultList(results) => Some(results),
            _ => None,
        }
    }
}

impl MiResult {
    pub fn find<'a>(results: &'a [Self], name: &str) -> Option<&'a MiValue> {
        results
            .iter()
            .find(|result| result.name == name)
            .map(|result| &result.value)
    }

    pub fn find_str<'a>(results: &'a [Self], name: &str) -> Option<&'a str> {
        Self::find(results, name)?.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_record_kind_round_trips_through_json() {
        let records = [
            MiRecord::Result {
                token: Some(1),
                class: "done".into(),
                results: vec![],
            },
            MiRecord::ExecAsync {
                token: None,
                class: "stopped".into(),
                results: vec![],
            },
            MiRecord::StatusAsync {
                token: None,
                class: "download".into(),
                results: vec![],
            },
            MiRecord::NotifyAsync {
                token: None,
                class: "thread-created".into(),
                results: vec![],
            },
            MiRecord::ConsoleStream(b"console".to_vec()),
            MiRecord::TargetStream(vec![0xff, 0]),
            MiRecord::LogStream(b"log".to_vec()),
            MiRecord::Prompt,
        ];
        for record in records {
            let value = serde_json::to_value(&record).unwrap();
            assert_eq!(serde_json::from_value::<MiRecord>(value).unwrap(), record);
        }
    }
}
