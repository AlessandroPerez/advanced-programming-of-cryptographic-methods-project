
/// Helper function to parse a `[u8; 32]` from a JSON array
pub fn parse_key_array(value: &serde_json::Value) -> Result<[u8; 32], warp::Rejection> {
    let array = value
        .as_array()
        .ok_or_else(|| warp::reject::custom(DeserializationError))?;

    if array.len() != 32 {
        return Err(warp::reject::custom(DeserializationError));
    }

    let mut result = [0u8; 32];
    for (i, v) in array.iter().enumerate() {
        result[i] = v.as_u64().ok_or_else(|| warp::reject::custom(DeserializationError))? as u8;
    }
    Ok(result)
}

/// Helper function to parse a `[u8; 64]` from a JSON array
pub fn parse_key_array64(value: &serde_json::Value) -> Result<[u8; 64], warp::Rejection> {
    let array = value
        .as_array()
        .ok_or_else(|| warp::reject::custom(DeserializationError))?;

    if array.len() != 64 {
        return Err(warp::reject::custom(DeserializationError));
    }

    let mut result = [0u8; 64];
    for (i, v) in array.iter().enumerate() {
        result[i] = v.as_u64()
            .ok_or_else(|| warp::reject::custom(DeserializationError))? as u8;
    }
    Ok(result)
}

/// Custom error type for better rejections
#[derive(Debug)]
pub struct DeserializationError;

impl warp::reject::Reject for DeserializationError {}