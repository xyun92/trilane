#[derive(Default)]
struct ChatStreamState {
    response_id: Option<String>,
    created: bool,
    message_started: bool,
    reasoning_started: bool,
    text: String,
    reasoning: String,
    usage: Option<Value>,
    tool_calls: BTreeMap<u64, ToolCallAccumulator>,
    tool_calls_emitted: bool,
}

#[derive(Default)]
struct ToolCallAccumulator {
    call_id: String,
    name: String,
    arguments: String,
}

impl ChatStreamState {
    fn response_id(&self) -> String {
        self.response_id
            .clone()
            .unwrap_or_else(|| "chatcmpl-proxy-stream".to_string())
    }

    fn ensure_response_created(&mut self, chunk: &Value, events: &mut Vec<Value>) {
        if self.response_id.is_none() {
            if let Some(id) = chunk.get("id").and_then(Value::as_str) {
                self.response_id = Some(id.to_string());
            }
        }
        if !self.created {
            self.created = true;
            events.push(json!({
                "type": "response.created",
                "response": {
                    "id": self.response_id(),
                },
            }));
        }
    }

    fn push_text_delta(&mut self, delta: &str, events: &mut Vec<Value>) {
        if !self.message_started {
            self.message_started = true;
            events.push(json!({
                "type": "response.output_item.added",
                "item": {
                    "type": "message",
                    "role": "assistant",
                    "id": self.message_id(),
                    "content": [{"type": "output_text", "text": ""}],
                },
            }));
        }
        self.text.push_str(delta);
        events.push(json!({
            "type": "response.output_text.delta",
            "delta": delta,
        }));
    }

    fn push_reasoning_delta(&mut self, delta: &str, events: &mut Vec<Value>) {
        if !self.reasoning_started {
            self.reasoning_started = true;
            events.push(json!({
                "type": "response.output_item.added",
                "item": {
                    "type": "reasoning",
                    "id": self.reasoning_id(),
                    "summary": [],
                },
            }));
        }
        self.reasoning.push_str(delta);
        events.push(json!({
            "type": "response.reasoning_summary_text.delta",
            "delta": delta,
            "summary_index": 0,
        }));
    }

    fn message_id(&self) -> String {
        format!("{}-msg", self.response_id())
    }

    fn reasoning_id(&self) -> String {
        format!("{}-reasoning", self.response_id())
    }

    fn emit_tool_calls(&mut self, events: &mut Vec<Value>) {
        if self.tool_calls_emitted {
            return;
        }
        self.tool_calls_emitted = true;
        for tool_call in self.tool_calls.values() {
            if tool_call.name.is_empty() {
                continue;
            }
            events.push(json!({
                "type": "response.output_item.done",
                "item": {
                    "type": "function_call",
                    "call_id": if tool_call.call_id.is_empty() {
                        format!("{}-tool", self.response_id())
                    } else {
                        tool_call.call_id.clone()
                    },
                    "name": tool_call.name,
                    "arguments": tool_call.arguments,
                },
            }));
        }
    }

    fn finish_events(&mut self) -> Vec<Value> {
        let mut events = Vec::new();
        if !self.created {
            events.push(json!({
                "type": "response.created",
                "response": {
                    "id": self.response_id(),
                },
            }));
            self.created = true;
        }
        self.emit_tool_calls(&mut events);
        if self.reasoning_started {
            events.push(json!({
                "type": "response.output_item.done",
                "item": {
                    "type": "reasoning",
                    "id": self.reasoning_id(),
                    "summary": [{"type": "summary_text", "text": self.reasoning}],
                },
            }));
        }
        if self.message_started {
            events.push(json!({
                "type": "response.output_item.done",
                "item": {
                    "type": "message",
                    "role": "assistant",
                    "id": self.message_id(),
                    "content": [{"type": "output_text", "text": self.text}],
                },
            }));
        }
        events.push(json!({
            "type": "response.completed",
            "response": {
                "id": self.response_id(),
                "usage": self.usage.clone().unwrap_or_else(|| normalize_usage(None)),
            },
        }));
        events
    }
}

fn chat_stream_line_to_response_events(line: &str, state: &mut ChatStreamState) -> Vec<Value> {
    let Some(data) = line.strip_prefix("data:") else {
        return Vec::new();
    };
    let data = data.trim();
    if data.is_empty() {
        return Vec::new();
    }
    if data == "[DONE]" {
        return Vec::new();
    }
    let Ok(chunk) = serde_json::from_str::<Value>(data) else {
        return Vec::new();
    };

    let mut events = Vec::new();
    state.ensure_response_created(&chunk, &mut events);
    if let Some(usage) = chunk.get("usage") {
        if !usage.is_null() {
            state.usage = Some(normalize_usage(Some(usage)));
        }
    }

    let choices = chunk
        .get("choices")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for choice in choices {
        if let Some(delta) = choice.get("delta") {
            if let Some(reasoning) = delta.get("reasoning_content").and_then(Value::as_str) {
                if !reasoning.is_empty() {
                    state.push_reasoning_delta(reasoning, &mut events);
                }
            }
            if let Some(content) = delta.get("content").and_then(Value::as_str) {
                if !content.is_empty() {
                    state.push_text_delta(content, &mut events);
                }
            }
            if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                absorb_tool_call_deltas(tool_calls, state);
            }
        }
        if choice
            .get("finish_reason")
            .and_then(Value::as_str)
            .is_some_and(|reason| reason == "tool_calls")
        {
            state.emit_tool_calls(&mut events);
        }
    }

    events
}

fn absorb_tool_call_deltas(tool_calls: &[Value], state: &mut ChatStreamState) {
    for tool_call in tool_calls {
        let index = tool_call.get("index").and_then(Value::as_u64).unwrap_or(0);
        let entry = state.tool_calls.entry(index).or_default();
        if let Some(id) = tool_call.get("id").and_then(Value::as_str) {
            if !id.is_empty() {
                entry.call_id = id.to_string();
            }
        }
        let Some(function) = tool_call.get("function") else {
            continue;
        };
        if let Some(name) = function.get("name").and_then(Value::as_str) {
            entry.name.push_str(name);
        }
        if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
            entry.arguments.push_str(arguments);
        }
    }
}

fn chat_message_to_output_events(response_id: &str, message: &Value) -> Vec<Value> {
    let mut events = Vec::new();
    if let Some(reasoning) = extract_reasoning_content(message) {
        if !reasoning.trim().is_empty() {
            events.push(json!({
                "type": "response.output_item.done",
                "item": {
                    "type": "reasoning",
                    "id": format!("{response_id}-reasoning"),
                    "summary": [{"type": "summary_text", "text": reasoning}],
                },
            }));
        }
    }

    let raw_text = extract_message_text(message).unwrap_or_default();
    let ParsedTextToolCalls {
        visible_text,
        tool_calls: parsed_tool_calls,
    } = parse_text_tool_calls(response_id, &raw_text);
    if !visible_text.trim().is_empty() {
        let item_id = format!("{response_id}-msg");
        events.push(json!({
            "type": "response.output_item.done",
            "item": {
                "type": "message",
                "role": "assistant",
                "id": item_id,
                "content": [{
                    "type": "output_text",
                    "text": visible_text,
                }],
            },
        }));
    }

    if let Some(tool_calls) = message.get("tool_calls").and_then(Value::as_array) {
        for tool_call in tool_calls {
            if let Some(event) = chat_tool_call_to_response_event(tool_call) {
                events.push(event);
            }
        }
    }

    for tool_call in parsed_tool_calls {
        events.push(tool_call_to_response_event(tool_call));
    }

    if events.is_empty() {
        let item_id = format!("{response_id}-msg");
        events.push(json!({
            "type": "response.output_item.done",
            "item": {
                "type": "message",
                "role": "assistant",
                "id": item_id,
                "content": [{
                    "type": "output_text",
                    "text": "",
                }],
            },
        }));
    }

    events
}

fn chat_tool_call_to_response_event(tool_call: &Value) -> Option<Value> {
    let call_id = tool_call.get("id").and_then(Value::as_str)?;
    let function = tool_call.get("function")?;
    let name = function.get("name").and_then(Value::as_str)?;
    let arguments = function
        .get("arguments")
        .and_then(Value::as_str)
        .unwrap_or("{}");
    Some(json!({
        "type": "response.output_item.done",
        "item": {
            "type": "function_call",
            "call_id": call_id,
            "name": name,
            "arguments": arguments,
        },
    }))
}

#[derive(Debug, PartialEq)]
struct ParsedTextToolCalls {
    visible_text: String,
    tool_calls: Vec<TextToolCall>,
}

#[derive(Debug, PartialEq)]
struct TextToolCall {
    call_id: String,
    name: String,
    arguments: String,
}

fn parse_text_tool_calls(response_id: &str, text: &str) -> ParsedTextToolCalls {
    let mut visible_text = String::new();
    let mut tool_calls = Vec::new();
    let mut rest = text;

    while let Some(start) = rest.find("<tool_call>") {
        visible_text.push_str(&rest[..start]);
        let after_start = &rest[start + "<tool_call>".len()..];
        let Some(end) = after_start.find("</tool_call>") else {
            visible_text.push_str(&rest[start..]);
            return ParsedTextToolCalls {
                visible_text,
                tool_calls,
            };
        };
        let block = &after_start[..end];
        if let Some(mut tool_call) = parse_tool_call_block(block) {
            tool_call.call_id = format!("{response_id}-tool-{}", tool_calls.len());
            tool_calls.push(tool_call);
        } else {
            visible_text
                .push_str(&rest[start..start + "<tool_call>".len() + end + "</tool_call>".len()]);
        }
        rest = &after_start[end + "</tool_call>".len()..];
    }

    visible_text.push_str(rest);
    ParsedTextToolCalls {
        visible_text: visible_text.trim_end().to_string(),
        tool_calls,
    }
}

fn parse_tool_call_block(block: &str) -> Option<TextToolCall> {
    let function_start = block.find("<function=")? + "<function=".len();
    let function_end = block[function_start..].find('>')? + function_start;
    let raw_name = block[function_start..function_end].trim();
    let name = match raw_name {
        "shell" | "exec" | "bash" | "terminal" | "shell_command" => "exec_command",
        other => other,
    };
    let args = if name == "exec_command" {
        parse_exec_command_args(block)?
    } else {
        parse_generic_tool_args(name, block)?
    };

    Some(TextToolCall {
        call_id: String::new(),
        name: name.to_string(),
        arguments: args.to_string(),
    })
}

fn parse_exec_command_args(block: &str) -> Option<Value> {
    let command = extract_parameter(block, "command")
        .or_else(|| extract_parameter(block, "cmd"))
        .or_else(|| extract_parameter(block, "script"))?;
    let mut args = json!({
        "cmd": command.trim(),
    });
    if let Some(workdir) =
        extract_parameter(block, "workdir").or_else(|| extract_parameter(block, "cwd"))
    {
        args["workdir"] = json!(workdir.trim());
    }
    if let Some(timeout_ms) = extract_parameter(block, "timeout_ms")
        .or_else(|| extract_parameter(block, "timeout"))
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        args["timeout_ms"] = json!(timeout_ms);
    }
    Some(args)
}

fn parse_generic_tool_args(name: &str, block: &str) -> Option<Value> {
    let mut args = serde_json::Map::new();
    for (raw_key, raw_value) in extract_parameters(block) {
        let key = raw_key.trim();
        let value = raw_value.trim();
        if key.is_empty() {
            continue;
        }
        if key.starts_with('{') {
            let object = serde_json::from_str::<Value>(key).ok()?;
            if let Some(object) = object.as_object() {
                args.extend(object.clone());
            }
            continue;
        }
        if key.starts_with('[') {
            let parameter_name = if name == "update_plan" {
                "plan"
            } else {
                "items"
            };
            args.insert(parameter_name.to_string(), parse_parameter_json_value(key));
            continue;
        }
        args.insert(key.to_string(), parse_parameter_json_value(value));
    }
    (!args.is_empty()).then_some(Value::Object(args))
}

fn extract_parameter(block: &str, name: &str) -> Option<String> {
    let start_tag = format!("<parameter={name}>");
    let start = block.find(&start_tag)? + start_tag.len();
    let end = block[start..].find("</parameter>")? + start;
    Some(block[start..end].to_string())
}

fn extract_parameters(block: &str) -> Vec<(String, String)> {
    let mut parameters = Vec::new();
    let mut rest = block;
    while let Some(tag_start) = rest.find("<parameter=") {
        let after_tag = &rest[tag_start + "<parameter=".len()..];
        let Some(tag_end_offset) = after_tag.find('>') else {
            break;
        };
        let raw_key = after_tag[..tag_end_offset].trim().to_string();
        let value_start = tag_start + "<parameter=".len() + tag_end_offset + 1;
        let after_value = &rest[value_start..];
        let Some(value_end_offset) = after_value.find("</parameter>") else {
            break;
        };
        parameters.push((raw_key, after_value[..value_end_offset].to_string()));
        rest = &after_value[value_end_offset + "</parameter>".len()..];
    }
    parameters
}

fn parse_parameter_json_value(value: &str) -> Value {
    serde_json::from_str::<Value>(value).unwrap_or_else(|_| json!(value.trim()))
}

fn tool_call_to_response_event(tool_call: TextToolCall) -> Value {
    json!({
        "type": "response.output_item.done",
        "item": {
            "type": "function_call",
            "call_id": tool_call.call_id,
            "name": tool_call.name,
            "arguments": tool_call.arguments,
        },
    })
}

fn extract_message_text(message: &Value) -> Option<String> {
    message
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn extract_reasoning_content(message: &Value) -> Option<String> {
    message
        .get("reasoning_content")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn normalize_usage(usage: Option<&Value>) -> Value {
    let input_tokens = usage
        .and_then(|usage| usage.get("prompt_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let output_tokens = usage
        .and_then(|usage| usage.get("completion_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let total_tokens = usage
        .and_then(|usage| usage.get("total_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(input_tokens + output_tokens);

    json!({
        "input_tokens": input_tokens,
        "input_tokens_details": null,
        "output_tokens": output_tokens,
        "output_tokens_details": null,
        "total_tokens": total_tokens,
    })
}

