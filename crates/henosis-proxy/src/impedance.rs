//! Three-state AI Impedance Controller and exposure topic extraction.
//!
//! - `Open`: forwards requests unchanged and logs unverified exposure telemetry.
//! - `Socratic`: deterministically injects a system constraint into supported
//!   OpenAI (`/v1/chat/completions`, `/v1/responses`) and Anthropic
//!   (`/v1/messages`) JSON payloads, rejecting unrecognized endpoints/payloads
//!   rather than silently bypassing impedance.
//! - `Blackout`: rejects every request before upstream dispatch.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;

pub const SOCRATIC_DIRECTIVE: &str = "HENOSIS SOCRATIC IMPEDANCE ACTIVE: Do not output complete turnkey solutions, full runnable implementations, or final proof steps. Instead, expose hidden assumptions, name governing invariants, ask a discriminating question, and point to the smallest falsifiable subproblem so the human executes the step.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ImpedanceMode {
    #[default]
    Open,
    Socratic,
    Blackout,
}

impl ImpedanceMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "open" => Ok(Self::Open),
            "socratic" => Ok(Self::Socratic),
            "blackout" => Ok(Self::Blackout),
            _ => Err("impedance mode must be 'open', 'socratic', or 'blackout'".into()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Socratic => "socratic",
            Self::Blackout => "blackout",
        }
    }
}

impl fmt::Display for ImpedanceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Normalize path by stripping any query string before matching endpoints.
fn clean_path(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

/// Rewrite a supported LLM request JSON body to enforce Socratic Impedance.
/// Fails closed if the endpoint or JSON structure cannot be rewritten cleanly.
pub fn rewrite_socratic(path: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let endpoint = clean_path(path);
    let mut doc: Value =
        serde_json::from_slice(body).map_err(|err| format!("invalid JSON payload: {err}"))?;
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| "request root must be a JSON object".to_owned())?;

    if endpoint.ends_with("/chat/completions") {
        let messages = obj
            .get_mut("messages")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "chat completions request requires a 'messages' array".to_owned())?;
        messages.insert(
            0,
            json!({
                "role": "system",
                "content": SOCRATIC_DIRECTIVE,
            }),
        );
    } else if endpoint.ends_with("/messages") {
        match obj.remove("system") {
            None => {
                obj.insert("system".into(), Value::String(SOCRATIC_DIRECTIVE.into()));
            }
            Some(Value::String(existing)) => {
                obj.insert(
                    "system".into(),
                    Value::String(format!("{SOCRATIC_DIRECTIVE}\n\n{existing}")),
                );
            }
            Some(Value::Array(mut blocks)) => {
                blocks.insert(
                    0,
                    json!({
                        "type": "text",
                        "text": SOCRATIC_DIRECTIVE,
                    }),
                );
                obj.insert("system".into(), Value::Array(blocks));
            }
            Some(_) => return Err("Anthropic 'system' field must be a string or array".into()),
        }
    } else if endpoint.ends_with("/responses") {
        match obj.remove("instructions") {
            None => {
                obj.insert(
                    "instructions".into(),
                    Value::String(SOCRATIC_DIRECTIVE.into()),
                );
            }
            Some(Value::String(existing)) => {
                obj.insert(
                    "instructions".into(),
                    Value::String(format!("{SOCRATIC_DIRECTIVE}\n\n{existing}")),
                );
            }
            Some(_) => return Err("responses 'instructions' field must be a string".into()),
        }
    } else {
        return Err(format!(
            "endpoint '{endpoint}' does not support verified Socratic rewriting"
        ));
    }

    serde_json::to_vec(&doc).map_err(|err| err.to_string())
}

const STOPWORDS: &[&str] = &[
    "about", "after", "again", "being", "below", "between", "could", "doing", "during", "every",
    "explain", "first", "from", "given", "having", "other", "please", "should", "their", "there",
    "these", "thing", "think", "those", "through", "under", "using", "where", "which", "while",
    "would", "write",
];

/// Extract non-secret model name and up to 6 sanitized topic keywords from a
/// JSON request body for the Unverified Exposure Quarantine log.
pub fn extract_exposure_summary(body: &[u8]) -> (Option<String>, Vec<String>) {
    let Ok(doc) = serde_json::from_slice::<Value>(body) else {
        return (None, Vec::new());
    };
    let model = doc
        .get("model")
        .and_then(Value::as_str)
        .map(|m| m.chars().filter(|c| !c.is_control()).take(64).collect());

    let mut collected = String::new();
    if let Some(messages) = doc.get("messages").and_then(Value::as_array) {
        for msg in messages.iter().rev() {
            if msg.get("role").and_then(Value::as_str) == Some("user") {
                if let Some(text) = msg.get("content").and_then(Value::as_str) {
                    collected.push_str(text);
                    break;
                }
            }
        }
    } else if let Some(input) = doc.get("input").and_then(Value::as_str) {
        collected.push_str(input);
    }

    let mut topics: Vec<String> = Vec::new();
    for raw in collected.split(|c: char| !c.is_ascii_alphanumeric() && c != '-') {
        let word = raw.trim_matches('-').to_ascii_lowercase();
        if word.len() < 5 || word.len() > 32 {
            continue;
        }
        if !word.bytes().any(|b| b.is_ascii_alphabetic()) {
            continue;
        }
        if STOPWORDS.contains(&word.as_str()) || topics.contains(&word) {
            continue;
        }
        topics.push(word);
        if topics.len() >= 6 {
            break;
        }
    }
    (model, topics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_openai_anthropic_and_responses_payloads_and_fails_closed() {
        let openai = br#"{"model":"gpt-test","messages":[{"role":"user","content":"Derive Fourier transform convolution theorem"}]}"#;
        let (model, topics) = extract_exposure_summary(openai);
        assert_eq!(model.as_deref(), Some("gpt-test"));
        assert!(topics.contains(&"fourier".to_owned()));
        assert!(topics.contains(&"convolution".to_owned()));

        let out = rewrite_socratic("/v1/chat/completions", openai).unwrap();
        let parsed: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["messages"][0]["role"], "system");
        assert!(parsed["messages"][0]["content"]
            .as_str()
            .unwrap()
            .contains("HENOSIS SOCRATIC IMPEDANCE"));
        assert_eq!(parsed["messages"][1]["role"], "user");

        let anthropic = br#"{"model":"claude-test","system":"Be concise.","messages":[{"role":"user","content":"Prove Cayley-Hamilton"}]}"#;
        let out_ant = rewrite_socratic("/v1/messages", anthropic).unwrap();
        let parsed_ant: Value = serde_json::from_slice(&out_ant).unwrap();
        let sys = parsed_ant["system"].as_str().unwrap();
        assert!(sys.starts_with("HENOSIS SOCRATIC IMPEDANCE"));
        assert!(sys.ends_with("Be concise."));

        let responses = br#"{"model":"o-test","input":"Solve wave equation"}"#;
        let out_resp = rewrite_socratic("/v1/responses", responses).unwrap();
        let parsed_resp: Value = serde_json::from_slice(&out_resp).unwrap();
        assert!(parsed_resp["instructions"]
            .as_str()
            .unwrap()
            .contains("HENOSIS SOCRATIC IMPEDANCE"));

        assert!(rewrite_socratic("/v1/embeddings", br#"{"input":"hi"}"#).is_err());
        assert!(rewrite_socratic("/v1/chat/completions", b"not-json").is_err());
    }
}
