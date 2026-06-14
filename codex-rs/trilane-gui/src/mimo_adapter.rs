use axum::body::Body;
use axum::extract::State;
use axum::http::header;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::post;
use axum::Json;
use axum::Router;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;
use tracing::warn;

include!("mimo_adapter_core.inc.rs");
include!("mimo_adapter_translate.inc.rs");
include!("mimo_adapter_stream.inc.rs");

#[cfg(test)]
mod tests {
    use super::translate_chat_response_for_test;
    use super::translate_chat_stream_for_test;
    use super::translate_responses_request_for_test;
    use super::translate_responses_request_with_multimodal_model_for_test;
    use pretty_assertions::assert_eq;
    use serde_json::json;

    include!("mimo_adapter_tests.inc.rs");
}
