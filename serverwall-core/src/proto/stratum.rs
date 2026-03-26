/// Stratum V1 JSON-RPC message representation.
///
/// Stratum uses newline-delimited JSON over a persistent TCP connection.
/// Each message is a JSON object with `id`, `method`/`result`/`error` fields.
#[derive(Debug, Clone)]
pub struct StratumMessage {
    pub id:     Option<serde_json::Value>,
    pub method: Option<String>,
    pub params: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub error:  Option<serde_json::Value>,
}

/// Parse one newline-terminated JSON line into a `StratumMessage`.
/// Returns `None` if the line is not valid JSON or is not an object.
pub fn parse_line(line: &str) -> Option<StratumMessage> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let obj = v.as_object()?;
    Some(StratumMessage {
        id:     obj.get("id").cloned(),
        method: obj.get("method").and_then(|m| m.as_str()).map(str::to_string),
        params: obj.get("params").cloned(),
        result: obj.get("result").cloned(),
        error:  obj.get("error").cloned(),
    })
}

/// Returns `true` if `msg` is a successful response:
/// - `id` matches `expected_id`
/// - `result` is present and non-null
/// - `error` is absent or null
pub fn is_success_response(msg: &StratumMessage, expected_id: u64) -> bool {
    msg.id.as_ref().and_then(|v| v.as_u64()) == Some(expected_id)
        && msg.result.as_ref().map(|v| !v.is_null()).unwrap_or(false)
        && msg.error.as_ref().map(|v| v.is_null()).unwrap_or(true)
}

/// Extract the worker name from a `mining.authorize` message's params array.
/// Params[0] is the worker name (e.g. "wallet.workername").
pub fn extract_worker(msg: &StratumMessage) -> Option<String> {
    let params = msg.params.as_ref()?.as_array()?;
    params.first()?.as_str().map(str::to_string)
}
