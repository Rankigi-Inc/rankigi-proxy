use rankigi_proxy::event::derive_action_type;

#[test]
fn action_type_derivation() {
    assert_eq!(
        derive_action_type("POST", "api.openai.com", "/v1/chat/completions"),
        "llm.openai.chat"
    );
    assert_eq!(
        derive_action_type("POST", "api.openai.com", "/v1/embeddings"),
        "llm.openai.embeddings"
    );
    assert_eq!(
        derive_action_type("POST", "api.anthropic.com", "/v1/messages"),
        "llm.anthropic.messages"
    );
    assert_eq!(
        derive_action_type("POST", "localhost:11434", "/api/generate"),
        "llm.ollama.generate"
    );
    assert_eq!(
        derive_action_type("POST", "localhost:11434", "/api/chat"),
        "llm.ollama.chat"
    );
    assert_eq!(
        derive_action_type("POST", "127.0.0.1:11434", "/api/generate"),
        "llm.ollama.generate"
    );

    // Unknown hosts fall back to generic HTTP.
    assert_eq!(
        derive_action_type("GET", "example.com", "/foo"),
        "tool.http.get"
    );
    assert_eq!(
        derive_action_type("POST", "example.com", "/foo"),
        "tool.http.post"
    );
    assert_eq!(
        derive_action_type("PUT", "example.com", "/foo"),
        "tool.http.put"
    );
    assert_eq!(
        derive_action_type("DELETE", "example.com", "/foo"),
        "tool.http.delete"
    );

    // Case-insensitive method handling.
    assert_eq!(
        derive_action_type("post", "api.openai.com", "/v1/chat/completions"),
        "llm.openai.chat"
    );
}
