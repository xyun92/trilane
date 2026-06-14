fn response_items_to_chat_messages(items: &[Value]) -> Vec<Value> {
    let mut messages = Vec::new();
    let mut pending_reasoning: Option<String> = None;
    let mut pending_tool_calls: Vec<Value> = Vec::new();

    for item in items {
        let Some(item_type) = item.get("type").and_then(Value::as_str) else {
            continue;
        };

        match item_type {
            "reasoning" => {
                flush_pending_tool_calls(
                    &mut messages,
                    &mut pending_tool_calls,
                    &mut pending_reasoning,
                );
                pending_reasoning = reasoning_item_to_text(item);
            }
            "function_call" => {
                if let Some(tool_call) = response_function_call_to_chat_tool_call(item) {
                    pending_tool_calls.push(tool_call);
                }
            }
            "function_call_output" | "custom_tool_call_output" => {
                flush_pending_tool_calls(
                    &mut messages,
                    &mut pending_tool_calls,
                    &mut pending_reasoning,
                );
                if let Some(message) = response_tool_output_to_chat_message(item) {
                    messages.push(message);
                }
            }
            "message" => {
                flush_pending_tool_calls(
                    &mut messages,
                    &mut pending_tool_calls,
                    &mut pending_reasoning,
                );
                if let Some(mut message) = response_message_to_chat_message(item) {
                    if message.get("role").and_then(Value::as_str) == Some("assistant") {
                        if let Some(reasoning) = pending_reasoning.take() {
                            message["reasoning_content"] = json!(reasoning);
                        }
                    } else {
                        pending_reasoning = None;
                    }
                    messages.push(message);
                }
            }
            _ => {}
        }
    }

    flush_pending_tool_calls(
        &mut messages,
        &mut pending_tool_calls,
        &mut pending_reasoning,
    );

    messages
}

fn flush_pending_tool_calls(
    messages: &mut Vec<Value>,
    pending_tool_calls: &mut Vec<Value>,
    pending_reasoning: &mut Option<String>,
) {
    if pending_tool_calls.is_empty() {
        return;
    }
    let mut message = json!({
        "role": "assistant",
        "content": null,
        "tool_calls": std::mem::take(pending_tool_calls),
    });
    if let Some(reasoning) = pending_reasoning.take() {
        if !reasoning.trim().is_empty() {
            message["reasoning_content"] = json!(reasoning);
        }
    }
    messages.push(message);
}

fn response_message_to_chat_message(item: &Value) -> Option<Value> {
    let item_type = item.get("type").and_then(Value::as_str)?;
    match item_type {
        "message" => {
            let role = item
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("user")
                .to_string();
            let role = match role.as_str() {
                "assistant" | "system" | "user" => role,
                _ => "user".to_string(),
            };
            let content = content_to_chat_content(item.get("content"))?;
            Some(json!({
                "role": role,
                "content": content,
            }))
        }
        _ => None,
    }
}

fn reasoning_item_to_text(item: &Value) -> Option<String> {
    let text = content_to_text(item.get("content"))
        .or_else(|| content_to_text(item.get("summary")))
        .or_else(|| item.get("text").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default();
    (!text.trim().is_empty()).then_some(text)
}

fn response_function_call_to_chat_tool_call(item: &Value) -> Option<Value> {
    let call_id = item
        .get("call_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let name = item.get("name").and_then(Value::as_str).unwrap_or("tool");
    let arguments = item
        .get("arguments")
        .and_then(Value::as_str)
        .unwrap_or("{}");
    Some(json!({
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": arguments,
        },
    }))
}

fn response_tool_output_to_chat_message(item: &Value) -> Option<Value> {
    let call_id = item
        .get("call_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let output = content_to_text(item.get("output"))
        .or_else(|| content_to_text(item.get("content")))
        .unwrap_or_default();
    if call_id == "unknown" {
        Some(json!({
            "role": "user",
            "content": format!("Tool result:\n{output}"),
        }))
    } else {
        Some(json!({
            "role": "tool",
            "tool_call_id": call_id,
            "content": output,
        }))
    }
}

fn responses_tools_to_chat_tools(tools: Option<&Value>) -> Vec<Value> {
    let Some(Value::Array(tools)) = tools else {
        return Vec::new();
    };

    tools
        .iter()
        .filter_map(|tool| {
            let tool_type = tool.get("type").and_then(Value::as_str)?;
            if tool_type != "function" {
                return None;
            }
            let name = tool.get("name").and_then(Value::as_str)?;
            let mut function = json!({
                "name": name,
                "parameters": tool
                    .get("parameters")
                    .cloned()
                    .unwrap_or_else(|| json!({"type": "object", "properties": {}})),
            });
            if let Some(description) = tool.get("description") {
                function["description"] = description.clone();
            }
            if let Some(strict) = tool.get("strict") {
                function["strict"] = strict.clone();
            }
            Some(json!({
                "type": "function",
                "function": function,
            }))
        })
        .collect()
}

fn content_to_text(content: Option<&Value>) -> Option<String> {
    match content? {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Array(items) => {
            let mut parts = Vec::new();
            for item in items {
                if let Some(text) = item.get("text").and_then(Value::as_str) {
                    parts.push(text.to_string());
                } else if let Some(text) = item.get("output_text").and_then(Value::as_str) {
                    parts.push(text.to_string());
                } else if let Some(text) = item.get("reasoning_text").and_then(Value::as_str) {
                    parts.push(text.to_string());
                } else if let Some(text) = item.get("summary_text").and_then(Value::as_str) {
                    parts.push(text.to_string());
                }
            }
            (!parts.is_empty()).then_some(parts.join("\n"))
        }
        other => Some(other.to_string()),
    }
}

fn content_to_chat_content(content: Option<&Value>) -> Option<Value> {
    match content? {
        Value::Null => None,
        Value::String(text) => Some(json!(text)),
        Value::Array(items) => content_array_to_chat_content(items),
        other => Some(json!(other.to_string())),
    }
}

fn content_array_to_chat_content(items: &[Value]) -> Option<Value> {
    let mut text_parts = Vec::new();
    let mut chat_parts = Vec::new();
    let mut has_image = false;

    for item in items {
        if let Some(image_part) = image_content_part(item) {
            has_image = true;
            if !text_parts.is_empty() {
                chat_parts.push(json!({
                    "type": "text",
                    "text": text_parts.join("\n"),
                }));
                text_parts.clear();
            }
            chat_parts.push(image_part);
        } else if let Some(text) = text_content_part(item) {
            if has_image {
                chat_parts.push(json!({
                    "type": "text",
                    "text": text,
                }));
            } else {
                text_parts.push(text);
            }
        }
    }

    if has_image {
        (!chat_parts.is_empty()).then_some(Value::Array(chat_parts))
    } else {
        (!text_parts.is_empty()).then_some(json!(text_parts.join("\n")))
    }
}

fn text_content_part(item: &Value) -> Option<String> {
    item.get("text")
        .and_then(Value::as_str)
        .or_else(|| item.get("output_text").and_then(Value::as_str))
        .or_else(|| item.get("reasoning_text").and_then(Value::as_str))
        .or_else(|| item.get("summary_text").and_then(Value::as_str))
        .map(str::to_string)
}

fn image_content_part(item: &Value) -> Option<Value> {
    let item_type = item.get("type").and_then(Value::as_str)?;
    if item_type != "input_image" && item_type != "image_url" {
        return None;
    }

    let image_url = item
        .get("image_url")
        .and_then(image_url_value_to_string)
        .or_else(|| item.get("url").and_then(Value::as_str).map(str::to_string))?;
    Some(json!({
        "type": "image_url",
        "image_url": {
            "url": image_url,
        },
    }))
}

fn image_url_value_to_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_string)
        .or_else(|| value.get("url").and_then(Value::as_str).map(str::to_string))
}

fn messages_contain_images(messages: &[Value]) -> bool {
    messages.iter().any(|message| {
        message
            .get("content")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|item| item.get("type").and_then(Value::as_str) == Some("image_url"))
            })
    })
}

fn responses_sse_from_chat_response(response: Value) -> Response {
    let body = responses_sse_body_from_chat_response(response);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(Body::from(body))
        .expect("valid SSE response")
}

fn responses_sse_body_from_chat_response(response: Value) -> String {
    let response_id = response
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("chatcmpl-proxy");
    let message = response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"));
    let usage = normalize_usage(response.get("usage"));

    let mut events = vec![json!({
        "type": "response.created",
        "response": {
            "id": response_id,
        },
    })];

    let mut output_events = message
        .map(|message| chat_message_to_output_events(response_id, message))
        .unwrap_or_default();
    events.append(&mut output_events);

    events.push(json!({
        "type": "response.completed",
        "response": {
            "id": response_id,
            "usage": usage,
        },
    }));

    let mut body = String::new();
    for event in events {
        body.push_str(&response_sse_event(&event));
    }

    body
}

fn response_sse_event(event: &Value) -> String {
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("message");
    format!("event: {event_type}\ndata: {event}\n\n")
}
