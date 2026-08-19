package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/ghostguard/ghostguard/internal/model"
	"github.com/ghostguard/ghostguard/internal/policy"
)

type MCPServer struct {
	stdin    io.Reader
	stdout   io.Writer
	engine   *policy.Engine
	handlers map[string]Handler
	mu       sync.Mutex
}

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Handler func(params json.RawMessage) (interface{}, error)

func NewMCPServer(stdin io.Reader, stdout io.Writer, engine *policy.Engine) *MCPServer {
	s := &MCPServer{
		stdin:    stdin,
		stdout:   stdout,
		engine:   engine,
		handlers: make(map[string]Handler),
	}
	s.registerDefaults()
	return s
}

func (s *MCPServer) registerDefaults() {
	s.handlers["initialize"] = s.handleInitialize
	s.handlers["tools/list"] = s.handleToolsList
	s.handlers["tools/call"] = s.handleToolsCall
	s.handlers["ping"] = s.handlePing
}

func (s *MCPServer) RegisterHandler(method string, handler Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method] = handler
}

func (s *MCPServer) Serve(ctx context.Context) error {
	scanner := bufio.NewScanner(s.stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
			return io.EOF
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, -32700, "Parse error")
			continue
		}

		go s.handleRequest(ctx, &req)
	}
}

func (s *MCPServer) handleRequest(ctx context.Context, req *JSONRPCRequest) {
	s.mu.Lock()
	handler, ok := s.handlers[req.Method]
	s.mu.Unlock()

	if !ok {
		s.sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
		return
	}

	result, err := handler(req.Params)
	if err != nil {
		s.sendError(req.ID, -32603, err.Error())
		return
	}

	s.sendResponse(req.ID, result)
}

func (s *MCPServer) handleInitialize(params json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "ghostguard",
			"version": "0.1.0",
		},
	}, nil
}

func (s *MCPServer) handleToolsList(params json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"tools": []map[string]interface{}{
			{
				"name":        "ghostguard_status",
				"description": "Get GhostGuard proxy status and policy info",
				"inputSchema": map[string]interface{}{
					"type":       "object",
					"properties": map[string]interface{}{},
				},
			},
			{
			"name":        "ghostguard_test_tool",
				"description": "Test a tool call against loaded policies",
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"tool_name": map[string]interface{}{
							"type":        "string",
							"description": "Name of the tool to test",
						},
						"arguments": map[string]interface{}{
							"type":        "object",
							"description": "Tool arguments",
						},
					},
					"required": []string{"tool_name"},
				},
			},
		},
	}, nil
}

func (s *MCPServer) handleToolsCall(params json.RawMessage) (interface{}, error) {
	var callParams struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}

	if err := json.Unmarshal(params, &callParams); err != nil {
		return nil, fmt.Errorf("parsing call params: %w", err)
	}

	switch callParams.Name {
	case "ghostguard_status":
		return s.handleStatus()
	case "ghostguard_test_tool":
		return s.handleTestTool(callParams.Arguments)
	default:
		return nil, fmt.Errorf("unknown tool: %s", callParams.Name)
	}
}

func (s *MCPServer) handleStatus() (interface{}, error) {
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("GhostGuard v0.1.0 | Policies: %d loaded", s.engine.PolicyCount()),
			},
		},
	}, nil
}

func (s *MCPServer) handleTestTool(args map[string]interface{}) (interface{}, error) {
	toolName, _ := args["tool_name"].(string)
	toolArgs, _ := args["arguments"].(map[string]interface{})

	tc := &model.ToolCall{
		Name:      toolName,
		Arguments: toolArgs,
	}

	decision := s.engine.Evaluate(tc)

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf("Action: %s\nPolicy: %s\nReason: %s",
					decision.Action, decision.PolicyName, decision.Reason),
			},
		},
	}, nil
}

func (s *MCPServer) handlePing(params json.RawMessage) (interface{}, error) {
	return map[string]interface{}{}, nil
}

func (s *MCPServer) sendResponse(id interface{}, result interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	s.writeJSON(resp)
}

func (s *MCPServer) sendError(id interface{}, code int, message string) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
	}
	s.writeJSON(resp)
}

func (s *MCPServer) writeJSON(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	data = append(data, '\n')
	s.stdout.Write(data)
}

func RunMCPFromMain() {
	engine := policy.NewEngine()

	policyDir := os.Getenv("GHOSTGUARD_POLICY_DIR")
	if policyDir == "" {
		policyDir = "./policies"
	}

	policies, err := policy.LoadPoliciesFromDir(policyDir)
	if err == nil {
		for name, content := range policies {
			engine.LoadPolicy(name, content)
		}
	}

	srv := NewMCPServer(os.Stdin, os.Stdout, engine)
	srv.Serve(context.Background())
}
