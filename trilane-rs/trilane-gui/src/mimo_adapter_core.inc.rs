#[derive(Clone)]
struct AdapterState {
    upstream_base_url: String,
    api_key: String,
    multimodal_model: Option<String>,
    client: reqwest::Client,
}

pub async fn start(
    upstream_base_url: String,
    api_key: String,
    multimodal_model: Option<String>,
) -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("MiMo adapter bind failed: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("MiMo adapter local_addr failed: {e}"))?;

    let state = Arc::new(AdapterState {
        upstream_base_url,
        api_key,
        multimodal_model,
        client: reqwest::Client::new(),
    });
    let app = Router::new()
        .route("/responses", post(handle_responses))
        .route("/v1/responses", post(handle_responses))
        .with_state(state);

    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            tracing::warn!("MiMo adapter exited: {err}");
        }
    });

    let proxy_base_url = format!("http://{addr}/v1");
    info!("Started MiMo adapter at {proxy_base_url}");
    Ok(proxy_base_url)
}

#[cfg(test)]
pub fn translate_responses_request_for_test(request: &Value) -> Value {
    responses_to_chat_request(request, None)
}

#[cfg(test)]
pub fn translate_responses_request_with_multimodal_model_for_test(
    request: &Value,
    multimodal_model: &str,
) -> Value {
    responses_to_chat_request(request, Some(multimodal_model))
}

#[cfg(test)]
pub fn translate_chat_response_for_test(response: Value) -> String {
    responses_sse_body_from_chat_response(response)
}

#[cfg(test)]
pub fn translate_chat_stream_for_test(lines: &[&str]) -> String {
    let mut state = ChatStreamState::default();
    let mut body = String::new();
    for line in lines {
        for event in chat_stream_line_to_response_events(line, &mut state) {
            body.push_str(&response_sse_event(&event));
        }
    }
    for event in state.finish_events() {
        body.push_str(&response_sse_event(&event));
    }
    body
}

async fn handle_responses(
    State(state): State<Arc<AdapterState>>,
    Json(request): Json<Value>,
) -> Response {
    match forward_to_chat_completions(&state, request).await {
        Ok(response) => response,
        Err((status, message)) => (status, message).into_response(),
    }
}

async fn forward_to_chat_completions(
    state: &AdapterState,
    request: Value,
) -> Result<Response, (StatusCode, String)> {
    let mut chat_request = responses_to_chat_request(&request, state.multimodal_model.as_deref());
    let should_stream = request
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if should_stream {
        chat_request["stream"] = json!(true);
        chat_request["stream_options"] = json!({"include_usage": true});
    }
    let model = chat_request
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let message_count = chat_request
        .get("messages")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let upstream_url = format!(
        "{}/chat/completions",
        state.upstream_base_url.trim_end_matches('/')
    );
    warn!("MiMo adapter forwarding model={model} messages={message_count}");

    let upstream_response = state
        .client
        .post(upstream_url)
        .bearer_auth(&state.api_key)
        .json(&chat_request)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("MiMo adapter request failed: {e}"),
            )
        })?;

    let status = upstream_response.status();
    if should_stream && status.is_success() {
        warn!("MiMo adapter streaming Responses SSE");
        return Ok(stream_chat_response_as_responses_sse(upstream_response));
    }

    let body_text = upstream_response.text().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("MiMo adapter response read failed: {e}"),
        )
    })?;
    warn!(
        "MiMo adapter upstream status={} body_bytes={}",
        status.as_u16(),
        body_text.len()
    );
    let body: Value = serde_json::from_str(&body_text).map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("MiMo adapter invalid JSON response: {e}; body={body_text}"),
        )
    })?;

    if !status.is_success() {
        warn!("MiMo adapter upstream error body={body}");
        return Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            body.to_string(),
        ));
    }

    let response = responses_sse_from_chat_response(body);
    warn!("MiMo adapter returned Responses SSE");
    Ok(response.into_response())
}

fn stream_chat_response_as_responses_sse(mut upstream_response: reqwest::Response) -> Response {
    let stream = async_stream::stream! {
        let mut state = ChatStreamState::default();
        let mut buffer = String::new();
        loop {
            match upstream_response.chunk().await {
                Ok(Some(chunk)) => {
                    buffer.push_str(&String::from_utf8_lossy(&chunk));
                    while let Some(newline) = buffer.find('\n') {
                        let line = buffer[..newline].trim_end_matches('\r').to_string();
                        buffer = buffer[newline + 1..].to_string();
                        for event in chat_stream_line_to_response_events(&line, &mut state) {
                            yield Ok::<String, Infallible>(response_sse_event(&event));
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    let event = json!({
                        "type": "response.failed",
                        "response": {
                            "id": state.response_id(),
                            "error": {
                                "message": format!("MiMo adapter stream failed: {err}"),
                            },
                        },
                    });
                    yield Ok::<String, Infallible>(response_sse_event(&event));
                    return;
                }
            }
        }

        if !buffer.trim().is_empty() {
            for event in chat_stream_line_to_response_events(buffer.trim(), &mut state) {
                yield Ok::<String, Infallible>(response_sse_event(&event));
            }
        }

        for event in state.finish_events() {
            yield Ok::<String, Infallible>(response_sse_event(&event));
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from_stream(stream))
        .expect("valid SSE response")
}

fn responses_to_chat_request(request: &Value, multimodal_model: Option<&str>) -> Value {
    let mut messages = Vec::new();
    if let Some(instructions) = request.get("instructions").and_then(Value::as_str) {
        if !instructions.trim().is_empty() {
            messages.push(json!({
                "role": "system",
                "content": instructions,
            }));
        }
    }

    match request.get("input") {
        Some(Value::String(text)) => {
            messages.push(json!({
                "role": "user",
                "content": text,
            }));
        }
        Some(Value::Array(items)) => {
            messages.extend(response_items_to_chat_messages(items));
        }
        _ => {}
    }

    if messages.is_empty() {
        messages.push(json!({
            "role": "user",
            "content": "",
        }));
    }

    let mut model = request
        .get("model")
        .cloned()
        .unwrap_or_else(|| json!("mimo-v2.5"));
    let multimodal_model = multimodal_model.filter(|model| !model.trim().is_empty());
    let has_images = messages_contain_images(&messages);
    if let (true, Some(multimodal_model)) = (has_images, multimodal_model) {
        model = json!(multimodal_model);
    }

    let mut chat_request = json!({
        "model": model,
        "messages": messages,
        "stream": false,
        "thinking": {"type": "enabled"},
    });

    copy_request_field(request, &mut chat_request, "temperature");
    copy_request_field(request, &mut chat_request, "top_p");
    copy_request_field(request, &mut chat_request, "frequency_penalty");
    copy_request_field(request, &mut chat_request, "presence_penalty");
    copy_request_field(request, &mut chat_request, "stop");
    if let Some(max_tokens) = request
        .get("max_completion_tokens")
        .or_else(|| request.get("max_output_tokens"))
        .or_else(|| request.get("max_tokens"))
    {
        chat_request["max_completion_tokens"] = max_tokens.clone();
    }
    if let Some(thinking) = request.get("thinking") {
        chat_request["thinking"] = thinking.clone();
    } else if request
        .get("reasoning")
        .and_then(|reasoning| reasoning.get("effort"))
        .and_then(Value::as_str)
        .is_some_and(|effort| effort == "none" || effort == "minimal")
    {
        chat_request["thinking"] = json!({"type": "disabled"});
    }

    let tools = responses_tools_to_chat_tools(request.get("tools"));
    if !tools.is_empty() {
        chat_request["tools"] = Value::Array(tools);
        chat_request["tool_choice"] = request
            .get("tool_choice")
            .cloned()
            .unwrap_or_else(|| json!("auto"));
    }

    if let Some(parallel_tool_calls) = request.get("parallel_tool_calls") {
        chat_request["parallel_tool_calls"] = parallel_tool_calls.clone();
    }

    chat_request
}

fn copy_request_field(request: &Value, chat_request: &mut Value, field: &str) {
    if let Some(value) = request.get(field) {
        chat_request[field] = value.clone();
    }
}

