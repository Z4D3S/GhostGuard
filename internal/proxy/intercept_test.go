package proxy

import (
	"net/http"
	"testing"

	"github.com/ghostguard/ghostguard/internal/model"
)

func TestParseOpenAIToolCalls(t *testing.T) {
	p := &Proxy{}

	body := []byte(`{
		"messages": [
			{
				"tool_calls": [
					{
						"id": "call_123",
						"function": {
							"name": "exec",
							"arguments": "{\"command\":\"ls -la\"}"
						}
					}
				]
			}
		]
	}`)

	toolCalls := p.parseOpenAIToolCalls(body)

	if len(toolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(toolCalls))
	}
	if toolCalls[0].Name != "exec" {
		t.Errorf("expected tool name 'exec', got '%s'", toolCalls[0].Name)
	}
	if toolCalls[0].ID != "call_123" {
		t.Errorf("expected ID 'call_123', got '%s'", toolCalls[0].ID)
	}
	if toolCalls[0].Arguments["command"] != "ls -la" {
		t.Errorf("expected command 'ls -la', got '%v'", toolCalls[0].Arguments["command"])
	}
}

func TestParseOpenAIToolCallsMultiple(t *testing.T) {
	p := &Proxy{}

	body := []byte(`{
		"messages": [
			{
				"tool_calls": [
					{
						"id": "call_1",
						"function": {"name": "search_web", "arguments": "{\"query\":\"go\"}"}
					}
				]
			},
			{
				"tool_calls": [
					{
						"id": "call_2",
						"function": {"name": "exec", "arguments": "{\"command\":\"whoami\"}"}
					}
				]
			}
		]
	}`)

	toolCalls := p.parseOpenAIToolCalls(body)

	if len(toolCalls) != 2 {
		t.Fatalf("expected 2 tool calls, got %d", len(toolCalls))
	}
	if toolCalls[0].Name != "search_web" {
		t.Errorf("expected first tool 'search_web', got '%s'", toolCalls[0].Name)
	}
	if toolCalls[1].Name != "exec" {
		t.Errorf("expected second tool 'exec', got '%s'", toolCalls[1].Name)
	}
}

func TestParseOpenAIToolCallsInvalidJSON(t *testing.T) {
	p := &Proxy{}

	toolCalls := p.parseOpenAIToolCalls([]byte("not json"))

	if len(toolCalls) != 0 {
		t.Errorf("expected 0 tool calls for invalid JSON, got %d", len(toolCalls))
	}
}

func TestParseOpenAIToolCallsNoToolCalls(t *testing.T) {
	p := &Proxy{}

	body := []byte(`{"messages": [{"content": "hello"}]}`)

	toolCalls := p.parseOpenAIToolCalls(body)

	if len(toolCalls) != 0 {
		t.Errorf("expected 0 tool calls, got %d", len(toolCalls))
	}
}

func TestParseAnthropicToolCalls(t *testing.T) {
	p := &Proxy{}

	body := []byte(`{
		"messages": [
			{
				"content": [
					{
						"type": "tool_use",
						"name": "exec",
						"input": {"command": "rm -rf /"}
					}
				]
			}
		]
	}`)

	toolCalls := p.parseAnthropicToolCalls(body)

	if len(toolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(toolCalls))
	}
	if toolCalls[0].Name != "exec" {
		t.Errorf("expected tool name 'exec', got '%s'", toolCalls[0].Name)
	}
	if toolCalls[0].Arguments["command"] != "rm -rf /" {
		t.Errorf("expected command 'rm -rf /', got '%v'", toolCalls[0].Arguments["command"])
	}
}

func TestParseAnthropicToolCallsInvalidJSON(t *testing.T) {
	p := &Proxy{}

	toolCalls := p.parseAnthropicToolCalls([]byte("invalid"))

	if len(toolCalls) != 0 {
		t.Errorf("expected 0 tool calls for invalid JSON, got %d", len(toolCalls))
	}
}

func TestParseGeminiToolCalls(t *testing.T) {
	p := &Proxy{}

	body := []byte(`{
		"contents": [
			{
				"parts": [
					{
						"functionCall": {
							"name": "get_weather",
							"args": {"city": "Madrid"}
						}
					}
				]
			}
		]
	}`)

	toolCalls := p.parseGeminiToolCalls(body)

	if len(toolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(toolCalls))
	}
	if toolCalls[0].Name != "get_weather" {
		t.Errorf("expected tool name 'get_weather', got '%s'", toolCalls[0].Name)
	}
	if toolCalls[0].Arguments["city"] != "Madrid" {
		t.Errorf("expected city 'Madrid', got '%v'", toolCalls[0].Arguments["city"])
	}
}

func TestParseGeminiToolCallsInvalidJSON(t *testing.T) {
	p := &Proxy{}

	toolCalls := p.parseGeminiToolCalls([]byte("bad json"))

	if len(toolCalls) != 0 {
		t.Errorf("expected 0 tool calls for invalid JSON, got %d", len(toolCalls))
	}
}

func TestExtractToolResultsOpenAI(t *testing.T) {
	p := &Proxy{}

	body := []byte(`{
		"choices": [
			{
				"message": {
					"content": "File listing complete",
					"tool_calls": [
						{"id": "call_123", "function": {"name": "exec"}}
					]
				}
			}
		]
	}`)

	results := p.extractToolResults(body)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ToolCallID != "call_123" {
		t.Errorf("expected tool call ID 'call_123', got '%s'", results[0].ToolCallID)
	}
	if results[0].Content != "File listing complete" {
		t.Errorf("expected content 'File listing complete', got '%s'", results[0].Content)
	}
}

func TestExtractToolResultsAnthropic(t *testing.T) {
	p := &Proxy{}

	body := []byte(`{
		"content": [
			{
				"type": "tool_result",
				"tool_use_id": "toolu_123",
				"content": "done"
			}
		]
	}`)

	results := p.extractToolResults(body)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ToolCallID != "toolu_123" {
		t.Errorf("expected tool call ID 'toolu_123', got '%s'", results[0].ToolCallID)
	}
}

func TestExtractToolResultsInvalidJSON(t *testing.T) {
	p := &Proxy{}

	results := p.extractToolResults([]byte("invalid"))

	if len(results) != 0 {
		t.Errorf("expected 0 results for invalid JSON, got %d", len(results))
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()

	if id1 == "" {
		t.Error("expected non-empty ID")
	}
	if id1 == id2 {
		t.Error("expected unique IDs")
	}
	if len(id1) != 32 {
		t.Errorf("expected 32 hex chars, got %d", len(id1))
	}
}

func TestWriteDenyResponse(t *testing.T) {
	p := &Proxy{}
	w := &fakeResponseWriter{header: http.Header{}}

	decision := &model.PolicyDecision{
		Action:     model.DecisionDeny,
		PolicyName: "test",
		Reason:     "dangerous tool",
	}

	p.writeDenyResponse(w, decision)

	if w.statusCode != 403 {
		t.Errorf("expected status 403, got %d", w.statusCode)
	}
}

type fakeResponseWriter struct {
	header     http.Header
	statusCode int
	body       []byte
}

func (w *fakeResponseWriter) Header() http.Header {
	return w.header
}

func (w *fakeResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}

func (w *fakeResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}
