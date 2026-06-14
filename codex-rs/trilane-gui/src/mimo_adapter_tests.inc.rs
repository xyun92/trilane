    #[test]
    fn translates_responses_input_to_chat_completions_messages() {
        let translated = translate_responses_request_for_test(&json!({
            "model": "mimo-v2.5",
            "instructions": "You are terse.",
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "Reply pong"}]
                }
            ]
        }));

        assert_eq!(
            translated,
            json!({
                "model": "mimo-v2.5",
                "messages": [
                    {"role": "system", "content": "You are terse."},
                    {"role": "user", "content": "Reply pong"}
                ],
                "stream": false,
                "thinking": {"type": "enabled"}
            })
        );
    }

    #[test]
    fn routes_image_requests_to_configured_multimodal_model() {
        let translated = translate_responses_request_with_multimodal_model_for_test(
            &json!({
                "model": "mimo-v2.5-pro",
                "input": [{
                    "type": "message",
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "describe this screenshot"},
                        {"type": "input_image", "image_url": "data:image/png;base64,abc123"}
                    ]
                }]
            }),
            "mimo-v2.5",
        );

        assert_eq!(
            translated,
            json!({
                "model": "mimo-v2.5",
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "describe this screenshot"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,abc123"}}
                    ]
                }],
                "stream": false,
                "thinking": {"type": "enabled"}
            })
        );
    }

    #[test]
    fn ignores_null_reasoning_content_instead_of_emitting_literal_null() {
        let translated = translate_responses_request_for_test(&json!({
            "model": "mimo-v2.5-pro",
            "input": [
                {
                    "type": "reasoning",
                    "content": [null, {"type": "reasoning_text", "text": ""}]
                },
                {
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "exec_command",
                    "arguments": "{\"cmd\":\"pwd\"}"
                }
            ]
        }));

        assert_eq!(
            translated["messages"],
            json!([{
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call-1",
                    "type": "function",
                    "function": {
                        "name": "exec_command",
                        "arguments": "{\"cmd\":\"pwd\"}"
                    }
                }]
            }])
        );
    }

    #[test]
    fn translates_chat_completions_response_to_responses_sse() {
        let sse = translate_chat_response_for_test(json!({
            "id": "chatcmpl-1",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "pong"
                }
            }],
            "usage": {
                "prompt_tokens": 2,
                "completion_tokens": 1,
                "total_tokens": 3
            }
        }));

        assert!(sse.contains("event: response.created\n"));
        assert!(sse.contains("\"type\":\"response.output_item.done\""));
        assert!(sse.contains("\"text\":\"pong\""));
        assert!(sse.contains("event: response.completed\n"));
        assert!(sse.contains("\"input_tokens\":2"));
        assert!(sse.contains("\"output_tokens\":1"));
    }

    #[test]
    fn translates_chat_stream_to_responses_sse_deltas() {
        let sse = translate_chat_stream_for_test(&[
            r#"data: {"id":"chatcmpl-stream","choices":[{"delta":{"role":"assistant","content":"","reasoning_content":null},"finish_reason":null,"index":0}],"usage":null}"#,
            r#"data: {"id":"chatcmpl-stream","choices":[{"delta":{"content":null,"reasoning_content":"thinking"},"finish_reason":null,"index":0}],"usage":null}"#,
            r#"data: {"id":"chatcmpl-stream","choices":[{"delta":{"content":"po"},"finish_reason":null,"index":0}],"usage":null}"#,
            r#"data: {"id":"chatcmpl-stream","choices":[{"delta":{"content":"ng"},"finish_reason":"stop","index":0}],"usage":null}"#,
            r#"data: {"id":"chatcmpl-stream","choices":[],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}"#,
            "data: [DONE]",
        ]);

        assert!(sse.contains("event: response.created\n"));
        assert!(sse.contains("\"type\":\"response.reasoning_summary_text.delta\""));
        assert!(sse.contains("\"delta\":\"po\""));
        assert!(sse.contains("\"delta\":\"ng\""));
        assert!(sse.contains("\"text\":\"pong\""));
        assert!(sse.contains("\"input_tokens\":2"));
        assert!(sse.contains("\"output_tokens\":3"));
    }

    #[test]
    fn translates_chat_stream_tool_call_chunks_to_function_call() {
        let sse = translate_chat_stream_for_test(&[
            r#"data: {"id":"chatcmpl-tools","choices":[{"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call-1","type":"function","function":{"name":"exec_command","arguments":"{\"cmd\""}}]},"finish_reason":null,"index":0}],"usage":null}"#,
            r#"data: {"id":"chatcmpl-tools","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":":\"pwd\"}"}}]},"finish_reason":"tool_calls","index":0}],"usage":null}"#,
            "data: [DONE]",
        ]);

        assert!(sse.contains("\"type\":\"function_call\""));
        assert!(sse.contains("\"call_id\":\"call-1\""));
        assert!(sse.contains("\"name\":\"exec_command\""));
        assert!(sse.contains("{\\\"cmd\\\":\\\"pwd\\\"}"));
    }

    #[test]
    fn translates_responses_tools_to_chat_completions_tools() {
        let translated = translate_responses_request_for_test(&json!({
            "model": "mimo-v2.5",
            "input": "check target",
            "tools": [{
                "type": "function",
                "name": "exec_command",
                "description": "run a shell command",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "cmd": {"type": "string"}
                    },
                    "required": ["cmd"]
                }
            }],
            "parallel_tool_calls": true
        }));

        assert_eq!(
            translated["tools"],
            json!([{
                "type": "function",
                "function": {
                    "name": "exec_command",
                    "description": "run a shell command",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "cmd": {"type": "string"}
                        },
                        "required": ["cmd"]
                    }
                }
            }])
        );
        assert_eq!(translated["tool_choice"], json!("auto"));
        assert_eq!(translated["parallel_tool_calls"], json!(true));
    }

    #[test]
    fn translates_function_call_history_to_chat_tool_messages() {
        let translated = translate_responses_request_for_test(&json!({
            "model": "mimo-v2.5",
            "input": [
                {
                    "type": "reasoning",
                    "summary": [{"type": "summary_text", "text": "Need to inspect cwd"}]
                },
                {
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "exec_command",
                    "arguments": "{\"cmd\":\"pwd\"}"
                },
                {
                    "type": "function_call_output",
                    "call_id": "call-1",
                    "output": "/tmp\n"
                }
            ]
        }));

        assert_eq!(
            translated["messages"],
            json!([
                {
                    "role": "assistant",
                    "content": null,
                    "reasoning_content": "Need to inspect cwd",
                    "tool_calls": [{
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "exec_command",
                            "arguments": "{\"cmd\":\"pwd\"}"
                        }
                    }]
                },
                {
                    "role": "tool",
                    "tool_call_id": "call-1",
                    "content": "/tmp\n"
                }
            ])
        );
    }

    #[test]
    fn groups_multiple_function_calls_under_one_reasoned_assistant_message() {
        let translated = translate_responses_request_for_test(&json!({
            "model": "mimo-v2.5-pro",
            "input": [
                {
                    "type": "reasoning",
                    "content": [{"type": "reasoning_text", "text": "Run both checks"}]
                },
                {
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "exec_command",
                    "arguments": "{\"cmd\":\"pwd\"}"
                },
                {
                    "type": "function_call",
                    "call_id": "call-2",
                    "name": "exec_command",
                    "arguments": "{\"cmd\":\"ls\"}"
                }
            ]
        }));

        assert_eq!(
            translated["messages"],
            json!([{
                "role": "assistant",
                "content": null,
                "reasoning_content": "Run both checks",
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "exec_command",
                            "arguments": "{\"cmd\":\"pwd\"}"
                        }
                    },
                    {
                        "id": "call-2",
                        "type": "function",
                        "function": {
                            "name": "exec_command",
                            "arguments": "{\"cmd\":\"ls\"}"
                        }
                    }
                ]
            }])
        );
    }

    #[test]
    fn maps_common_responses_parameters_to_mimo_chat_completions() {
        let translated = translate_responses_request_for_test(&json!({
            "model": "mimo-v2.5-pro",
            "input": "hello",
            "max_output_tokens": 2048,
            "temperature": 0.7,
            "top_p": 0.9,
            "frequency_penalty": 0,
            "presence_penalty": 0,
            "stop": null,
            "reasoning": {"effort": "minimal"}
        }));

        assert_eq!(translated["max_completion_tokens"], json!(2048));
        assert_eq!(translated["temperature"], json!(0.7));
        assert_eq!(translated["top_p"], json!(0.9));
        assert_eq!(translated["frequency_penalty"], json!(0));
        assert_eq!(translated["presence_penalty"], json!(0));
        assert_eq!(translated["stop"], json!(null));
        assert_eq!(translated["thinking"], json!({"type": "disabled"}));
    }

    #[test]
    fn preserves_non_stream_reasoning_as_responses_reasoning_item() {
        let sse = translate_chat_response_for_test(json!({
            "id": "chatcmpl-reasoned",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "reasoning_content": "Need to answer briefly",
                    "content": "pong"
                }
            }]
        }));

        assert!(sse.contains("\"type\":\"reasoning\""));
        assert!(sse.contains("\"text\":\"Need to answer briefly\""));
        assert!(sse.contains("\"text\":\"pong\""));
    }

    #[test]
    fn translates_chat_tool_calls_to_responses_function_calls() {
        let sse = translate_chat_response_for_test(json!({
            "id": "chatcmpl-2",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call-abc",
                        "type": "function",
                        "function": {
                            "name": "exec_command",
                            "arguments": "{\"cmd\":\"curl -I http://localhost:3000\"}"
                        }
                    }]
                }
            }]
        }));

        assert!(sse.contains("\"type\":\"function_call\""));
        assert!(sse.contains("\"call_id\":\"call-abc\""));
        assert!(sse.contains("\"name\":\"exec_command\""));
        assert!(sse.contains("curl -I http://localhost:3000"));
    }

    #[test]
    fn translates_text_tool_call_markup_to_exec_command() {
        let sse = translate_chat_response_for_test(json!({
            "id": "chatcmpl-3",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Let me verify. <tool_call>\n<function=shell>\n<parameter=command>curl -s http://localhost:3000</parameter>\n<parameter=workdir>/tmp</parameter>\n</function>\n</tool_call>"
                }
            }]
        }));

        assert!(sse.contains("\"text\":\"Let me verify.\""));
        assert!(sse.contains("\"type\":\"function_call\""));
        assert!(sse.contains("\"call_id\":\"chatcmpl-3-tool-0\""));
        assert!(sse.contains("\"name\":\"exec_command\""));
        assert!(sse.contains("curl -s http://localhost:3000"));
        assert!(sse.contains("\\\"cmd\\\":\\\"curl -s http://localhost:3000\\\""));
        assert!(sse.contains("\\\"workdir\\\":\\\"/tmp\\\""));
        assert!(!sse.contains("<tool_call>"));
    }

    #[test]
    fn translates_text_update_plan_tool_call_with_unnamed_plan_parameter() {
        let sse = translate_chat_response_for_test(json!({
            "id": "chatcmpl-plan",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Planning. <tool_call>\n<function=update_plan>\n<parameter=explanation>S0 complete.</parameter>\n<parameter=[{\"status\":\"completed\",\"step\":\"S0\"},{\"status\":\"in_progress\",\"step\":\"S1\"}]></parameter>\n</function>\n</tool_call>"
                }
            }]
        }));

        assert!(sse.contains("\"text\":\"Planning.\""));
        assert!(sse.contains("\"type\":\"function_call\""));
        assert!(sse.contains("\"call_id\":\"chatcmpl-plan-tool-0\""));
        assert!(sse.contains("\"name\":\"update_plan\""));
        assert!(sse.contains("\\\"explanation\\\":\\\"S0 complete.\\\""));
        assert!(sse.contains("\\\"plan\\\":[{\\\"status\\\":\\\"completed\\\",\\\"step\\\":\\\"S0\\\"},{\\\"status\\\":\\\"in_progress\\\",\\\"step\\\":\\\"S1\\\"}]"));
        assert!(!sse.contains("<tool_call>"));
    }
