use super::SyncError;
use mtp::codec::{DataType, DataValue, EncodeLimits, TypeMap};
use serde_json::{Map, Value};

const FIELDS: &[(&str, DataType)] = &[
    ("operation", DataType::SyncOperation),
    ("scope", DataType::SyncScope),
    ("principal", DataType::SyncPrincipal),
    ("authority", DataType::SyncAuthority),
    ("user_id", DataType::SyncUserId),
    ("device_id", DataType::SyncDeviceId),
    (
        "authorization_generation",
        DataType::SyncAuthorizationGeneration,
    ),
    ("schema", DataType::SyncSchema),
    ("dictionary", DataType::SyncDictionary),
    ("page", DataType::SyncPage),
    ("limit", DataType::SyncLimit),
    ("after", DataType::SyncAfter),
    ("cursor", DataType::SyncCursor),
    ("page_id", DataType::SyncPageId),
    ("state", DataType::SyncState),
    ("head", DataType::SyncHead),
    ("floor", DataType::SyncFloor),
    ("next", DataType::SyncNext),
    ("records", DataType::SyncRecords),
    ("events", DataType::SyncEvents),
    ("sequence", DataType::SyncSequence),
    ("event_id", DataType::SyncEventId),
    ("entity", DataType::SyncEntity),
    ("key", DataType::SyncKey),
    ("value", DataType::SyncValue),
    ("record", DataType::SyncRecord),
    ("error", DataType::SyncError),
];

pub(super) fn validate(value: &DataValue, limit: usize) -> Result<(), SyncError> {
    value
        .validate_with_limits(EncodeLimits {
            max_depth: 32,
            max_values: 65_536,
            max_output_size: limit,
        })
        .map_err(|_| SyncError::Capacity)
}

pub(super) fn encode(value: Value, map: &TypeMap) -> Result<DataValue, SyncError> {
    encode_value(value, map, false, 0)
}

fn encode_value(
    value: Value,
    map: &TypeMap,
    record_value: bool,
    depth: usize,
) -> Result<DataValue, SyncError> {
    if depth > 32 {
        return Err(SyncError::Capacity);
    }
    Ok(match value {
        Value::Null => DataValue::Null,
        Value::Bool(value) => DataValue::Bool(value),
        Value::String(value) => DataValue::Str(value),
        Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                DataValue::UnsignedNumber(value.into())
            } else if let Some(value) = value.as_i64() {
                DataValue::SignedNumber(value.into())
            } else {
                DataValue::Float(value.as_f64().ok_or(SyncError::InvalidRequest)?)
            }
        }
        Value::Array(values) => DataValue::Array(
            values
                .into_iter()
                .map(|value| encode_value(value, map, record_value, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(values) if record_value => DataValue::Container(vec![(
            DataType::SyncEntries
                .try_to_id(map)
                .ok_or(SyncError::InvalidRequest)?,
            DataValue::Array(
                values
                    .into_iter()
                    .map(|(key, value)| {
                        Ok(DataValue::Array(vec![
                            DataValue::Str(key),
                            encode_value(value, map, true, depth + 2)?,
                        ]))
                    })
                    .collect::<Result<_, SyncError>>()?,
            ),
        )]),
        Value::Object(values) => DataValue::Container(
            values
                .into_iter()
                .map(|(key, value)| {
                    let field = FIELDS
                        .iter()
                        .find(|(name, _)| *name == key)
                        .ok_or(SyncError::InvalidRequest)?
                        .1;
                    Ok((
                        field.try_to_id(map).ok_or(SyncError::InvalidRequest)?,
                        encode_value(value, map, key == "value", depth + 1)?,
                    ))
                })
                .collect::<Result<_, SyncError>>()?,
        ),
    })
}

pub(super) fn decode(value: &DataValue, map: &TypeMap) -> Result<Value, SyncError> {
    decode_value(value, map, false)
}

fn decode_value(value: &DataValue, map: &TypeMap, record_value: bool) -> Result<Value, SyncError> {
    Ok(match value {
        DataValue::Null => Value::Null,
        DataValue::BoolTrue => Value::Bool(true),
        DataValue::BoolFalse => Value::Bool(false),
        DataValue::Bool(value) => Value::Bool(*value),
        DataValue::Str(value) => Value::String(value.clone()),
        DataValue::UnsignedNumber(value) => {
            Value::from(u64::try_from(*value).map_err(|_| SyncError::InvalidRequest)?)
        }
        DataValue::SignedNumber(value) => {
            Value::from(i64::try_from(*value).map_err(|_| SyncError::InvalidRequest)?)
        }
        DataValue::Float(value) => {
            Value::Number(serde_json::Number::from_f64(*value).ok_or(SyncError::InvalidRequest)?)
        }
        DataValue::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| decode_value(value, map, record_value))
                .collect::<Result<_, _>>()?,
        ),
        DataValue::Container(fields) if record_value => {
            let [(id, DataValue::Array(entries))] = fields.as_slice() else {
                return Err(SyncError::InvalidRequest);
            };
            if Some(*id) != DataType::SyncEntries.try_to_id(map) {
                return Err(SyncError::InvalidRequest);
            }
            let mut values = Map::new();
            for entry in entries {
                let DataValue::Array(pair) = entry else {
                    return Err(SyncError::InvalidRequest);
                };
                let [DataValue::Str(key), value] = pair.as_slice() else {
                    return Err(SyncError::InvalidRequest);
                };
                if values
                    .insert(key.clone(), decode_value(value, map, true)?)
                    .is_some()
                {
                    return Err(SyncError::InvalidRequest);
                }
            }
            Value::Object(values)
        }
        DataValue::Container(fields) => {
            let mut values = Map::new();
            for (id, value) in fields {
                let name = FIELDS
                    .iter()
                    .find(|(_, field)| field.try_to_id(map) == Some(*id))
                    .ok_or(SyncError::InvalidRequest)?
                    .0;
                if values
                    .insert(name.into(), decode_value(value, map, name == "value")?)
                    .is_some()
                {
                    return Err(SyncError::InvalidRequest);
                }
            }
            Value::Object(values)
        }
        _ => return Err(SyncError::InvalidRequest),
    })
}
