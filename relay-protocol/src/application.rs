//! Application effects prepared from an authenticated relay. These values do
//! not establish acceptance until the backend's fenced transaction commits.
use mtp::codec::CommunicationValue;
use serde::{Deserialize, Serialize};

impl ApplicationOperation {
    /// Check the signed application payload before reading any security fields.
    /// Transport correlation and authenticated identity live outside this payload.
    pub fn validate_frame_shape(frame: &CommunicationValue) -> Result<(), crate::Error> {
        let map = frame
            .type_map()
            .ok_or(crate::Error::Invalid("application dictionary"))?;
        if map.version.to_string() != crate::PROTECTED_TYPE_MAP_VERSION
            || map.fingerprint_hex().as_deref()
                != Some(crate::dictionary_fingerprint(&map.version.to_string())?.as_str())
        {
            return Err(crate::Error::Invalid("application dictionary"));
        }
        let allowed: &[&str] = match map.communication_type_name(frame.get_type().0) {
            Some("MessageSend") => &[
                "Content",
                "Files",
                "SendTime",
                "Height",
                "VersionNumber",
                "ReplyId",
            ],
            Some("MessageEdit") => &["Content", "Files", "SendTime", "VersionNumber"],
            Some("MessageFilesUpdate") => &["Files", "SendTime"],
            Some("MessageReactionAdd" | "MessageReactionRemove") => &["Reaction", "SendTime"],
            Some("MessageDelete" | "MessageDeleteLive") => &["SendTime"],
            Some("MessageState") => &["ChatPartnerId", "MessageState", "RelayMessageId", "EventAt"],
            Some("SetChatSecret") => &["SecretId", "VersionNumber", "WrappingScheme", "Recipients"],
            Some("AddConversation") => &["ChatPartnerId", "ChatPartnerName"],
            Some("FileShareOffered" | "FileShareRevoked") => &["Json"],
            _ => return Err(crate::Error::Invalid("application operation")),
        };
        let fields = frame
            .payload()
            .container_entries()
            .ok_or(crate::Error::Invalid("application fields"))?;
        let mut seen = std::collections::BTreeSet::new();
        for (id, _) in fields {
            if !seen.insert(id.0)
                || !allowed
                    .iter()
                    .chain(["SenderId", "ReceiverId", "ChatId"].iter())
                    .any(|name| map.data_type_name(id.0) == Some(*name))
            {
                return Err(crate::Error::Invalid(
                    "duplicate or unknown application field",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ApplicationOperation {
    FileShareOffered {
        offer: crate::files::ShareOffer,
    },
    FileShareRevoked {
        revoke: crate::files::ShareRevoke,
    },
    MessageSend {
        #[serde(with = "optional_base64_bytes")]
        content: Option<Vec<u8>>,
        files: Vec<MessageFile>,
        send_time: i64,
        height: i64,
        version: i64,
        reply_to: Option<i64>,
    },
    MessageEdit {
        #[serde(with = "optional_base64_bytes")]
        content: Option<Vec<u8>>,
        files: Vec<MessageFile>,
        send_time: i64,
        version: i64,
    },
    MessageFilesUpdate {
        files: Vec<MessageFile>,
        send_time: i64,
    },
    MessageReactionAdd {
        reaction: String,
        send_time: i64,
    },
    MessageReactionRemove {
        reaction: String,
        send_time: i64,
    },
    MessageDelete {
        send_time: i64,
    },
    MessageDeleteLive {
        send_time: i64,
    },
    MessageState {
        message_id: String,
        state: MessageState,
        event_at: i64,
    },
    MessageReceived {
        message_id: String,
        event_at: i64,
    },
    SetChatSecret {
        chat_id: String,
        version: i64,
        wrapping_scheme: String,
        sender: SecretCopy,
        recipient: SecretCopy,
    },
    AddConversation {
        name: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCopy {
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum MessageState {
    Read,
    Received,
    Sent,
    Sending,
}

impl MessageState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Received => "received",
            Self::Sent => "sent",
            Self::Sending => "sending",
        }
    }

    #[expect(
        clippy::should_implement_trait,
        reason = "unknown stored states cannot upgrade delivery"
    )]
    pub fn from_str(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "read" => Self::Read,
            "received" => Self::Received,
            "sent" => Self::Sent,
            _ => Self::Sending,
        }
    }

    pub fn upgrade(self, other: Self) -> Self {
        if self == Self::Read || other == Self::Read {
            Self::Read
        } else if self == Self::Received || other == Self::Received {
            Self::Received
        } else if self == Self::Sent || other == Self::Sent {
            Self::Sent
        } else {
            Self::Sending
        }
    }
}

/// A message attachment. `reference` is encrypted with the chat secret; only `status` may change without an edit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageFile {
    #[serde(with = "base64_bytes")]
    pub reference: Vec<u8>,
    pub status: Option<FileStatus>,
}

/// Upload state of an attachment; no status means the file is ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileStatus {
    Uploading,
    Cancelled,
    Failed,
}

/// JSON cannot carry raw bytes, so persisted JSON documents store ciphertext as base64.
pub mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        STANDARD.decode(encoded).map_err(serde::de::Error::custom)
    }
}

pub mod optional_base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => super::base64_bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        #[derive(Deserialize)]
        struct Wrapped(#[serde(with = "super::base64_bytes")] Vec<u8>);
        Ok(Option::<Wrapped>::deserialize(deserializer)?.map(|Wrapped(bytes)| bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_ciphertext_round_trips_as_base64() {
        let operation = ApplicationOperation::MessageEdit {
            content: Some(vec![0, 255, 7]),
            files: vec![MessageFile {
                reference: vec![1, 2, 3],
                status: None,
            }],
            send_time: 1,
            version: 2,
        };
        let json = serde_json::to_value(&operation).unwrap();
        assert_eq!(json["MessageEdit"]["content"], "AP8H");
        assert_eq!(json["MessageEdit"]["files"][0]["reference"], "AQID");

        let decoded: ApplicationOperation = serde_json::from_value(json).unwrap();
        assert!(matches!(
            decoded,
            ApplicationOperation::MessageEdit { content: Some(content), .. } if content == [0, 255, 7]
        ));

        let empty: ApplicationOperation = serde_json::from_value(serde_json::json!({
            "MessageEdit": {"content": null, "files": [], "send_time": 1, "version": 1}
        }))
        .unwrap();
        assert!(matches!(
            empty,
            ApplicationOperation::MessageEdit { content: None, .. }
        ));
    }
}
