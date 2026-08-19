package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ghostguard/ghostguard/internal/model"
)

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	event := &model.InterceptionEvent{
		ID:        generateID(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Host:      r.Host,
		Timestamp: start.UTC(),
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		p.logger.LogMessage("error", fmt.Sprintf("reading request body: %v", err))
		http.Error(w, "error reading request", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	event.RequestSize = len(body)

	if p.isAIEndpoint(r) {
		if !p.rateLimiter.Allow(r.Host) {
			p.logger.LogMessage("warn", fmt.Sprintf("rate limit exceeded for %s", r.Host))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"message": "GhostGuard: rate limit exceeded",
					"type":    "rate_limit_exceeded",
					"code":    "rate_limit_exceeded",
				},
			})
			return
		}

		toolCalls := p.extractToolCalls(r, body)
		event.ToolCalls = toolCalls

		for _, tc := range toolCalls {
			decision := p.engine.Evaluate(&tc)
			event.Decisions = append(event.Decisions, decision)

			if err := p.logger.LogDecision(&decision); err != nil {
				p.logger.LogMessage("error", fmt.Sprintf("logging decision: %v", err))
			}

			if decision.Action == model.DecisionDeny && !p.config.DryRun {
				p.alertMgr.AlertDecision(&decision)
				p.writeDenyResponse(w, &decision)
				return
			}

			if decision.Action == model.DecisionDeny && p.config.DryRun {
				p.logger.LogMessage("dry-run", fmt.Sprintf("would deny: %s - %s", tc.Name, decision.Reason))
			}

			anomalies := p.detector.Analyze(&tc)
			event.Anomalies = append(event.Anomalies, anomalies...)

			for _, a := range anomalies {
				p.alertMgr.AlertAnomaly(&a)
			}
		}
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), bytes.NewReader(body))
	if err != nil {
		p.logger.LogMessage("error", fmt.Sprintf("creating proxy request: %v", err))
		http.Error(w, "error creating request", http.StatusInternalServerError)
		return
	}

	copyHeaders(r.Header, proxyReq.Header)
	proxyReq.Header.Del("Proxy-Connection")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		p.logger.LogMessage("error", fmt.Sprintf("upstream request failed: %v", err))
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.LogMessage("error", fmt.Sprintf("reading response body: %v", err))
		http.Error(w, "error reading response", http.StatusInternalServerError)
		return
	}
	event.ResponseSize = len(respBody)
	event.UpstreamStatus = resp.StatusCode
	event.Duration = time.Since(start)

	if p.isAIEndpoint(r) {
		event.ToolResults = p.extractToolResults(respBody)
	}

	if err := p.logger.LogEvent(event); err != nil {
		p.logger.LogMessage("error", fmt.Sprintf("logging event: %v", err))
	}

	p.dash.RecordEvent(event)

	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	targetConn, err := p.dialTLS(host)
	if err != nil {
		p.logger.LogMessage("error", fmt.Sprintf("connecting to %s: %v", host, err))
		http.Error(w, "connection failed", http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.LogMessage("error", "http hijacking not supported")
		targetConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.logger.LogMessage("error", fmt.Sprintf("hijacking connection: %v", err))
		targetConn.Close()
		return
	}

	go p.tunnel(clientConn, targetConn)
}

func (p *Proxy) tunnel(client, target io.ReadWriteCloser) {
	defer client.Close()
	defer target.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)
	}()
	go func() {
		defer wg.Done()
		io.Copy(client, target)
	}()

	wg.Wait()
}

func (p *Proxy) isAIEndpoint(r *http.Request) bool {
	host := r.Host
	for _, target := range p.config.TargetHosts {
		if strings.Contains(host, target) {
			return true
		}
	}
	return false
}

func (p *Proxy) extractToolCalls(r *http.Request, body []byte) []model.ToolCall {
	var toolCalls []model.ToolCall

	if strings.Contains(r.URL.Path, "/chat/completions") {
		toolCalls = append(toolCalls, p.parseOpenAIToolCalls(body)...)
	}

	if strings.Contains(r.URL.Path, "/messages") && r.Header.Get("anthropic-version") != "" {
		toolCalls = append(toolCalls, p.parseAnthropicToolCalls(body)...)
	}

	if strings.Contains(r.Host, "generativelanguage.googleapis.com") {
		toolCalls = append(toolCalls, p.parseGeminiToolCalls(body)...)
	}

	return toolCalls
}

func (p *Proxy) parseOpenAIToolCalls(body []byte) []model.ToolCall {
	var raw struct {
		Messages []struct {
			ToolCalls []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	var toolCalls []model.ToolCall
	for _, msg := range raw.Messages {
		for _, tc := range msg.ToolCalls {
			var args map[string]interface{}
			json.Unmarshal([]byte(tc.Function.Arguments), &args)

			toolCalls = append(toolCalls, model.ToolCall{
				ID:        tc.ID,
				Name:      tc.Function.Name,
				Arguments: args,
				RawArgs:   tc.Function.Arguments,
			})
		}
	}
	return toolCalls
}

func (p *Proxy) parseAnthropicToolCalls(body []byte) []model.ToolCall {
	var raw struct {
		Messages []struct {
			Content []struct {
				Type  string                 `json:"type"`
				Name  string                 `json:"name,omitempty"`
				Input map[string]interface{} `json:"input,omitempty"`
			} `json:"content"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	var toolCalls []model.ToolCall
	for _, msg := range raw.Messages {
		for _, content := range msg.Content {
			if content.Type == "tool_use" {
				rawArgs, _ := json.Marshal(content.Input)
				toolCalls = append(toolCalls, model.ToolCall{
					ID:        fmt.Sprintf("tool-%s", content.Name),
					Name:      content.Name,
					Arguments: content.Input,
					RawArgs:   string(rawArgs),
				})
			}
		}
	}
	return toolCalls
}

func (p *Proxy) parseGeminiToolCalls(body []byte) []model.ToolCall {
	var raw struct {
		Contents []struct {
			Parts []struct {
				FunctionCall *struct {
					Name string                 `json:"name"`
					Args map[string]interface{} `json:"args"`
				} `json:"functionCall,omitempty"`
			} `json:"parts"`
		} `json:"contents"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}

	var toolCalls []model.ToolCall
	for _, content := range raw.Contents {
		for _, part := range content.Parts {
			if part.FunctionCall != nil {
				rawArgs, _ := json.Marshal(part.FunctionCall.Args)
				toolCalls = append(toolCalls, model.ToolCall{
					ID:        fmt.Sprintf("gemini-%s", part.FunctionCall.Name),
					Name:      part.FunctionCall.Name,
					Arguments: part.FunctionCall.Args,
					RawArgs:   string(rawArgs),
				})
			}
		}
	}
	return toolCalls
}

func (p *Proxy) extractToolResults(body []byte) []model.ToolResult {
	var results []model.ToolResult

	// Try OpenAI response format
	var openAIResp struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					ID       string `json:"id"`
					Function struct {
						Name string `json:"name"`
					} `json:"function"`
				} `json:"tool_calls"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &openAIResp); err == nil {
		for _, choice := range openAIResp.Choices {
			for _, tc := range choice.Message.ToolCalls {
				results = append(results, model.ToolResult{
					ToolCallID: tc.ID,
					Content:    choice.Message.Content,
					IsError:    false,
				})
			}
		}
		if len(results) > 0 {
			return results
		}
	}

	// Try Anthropic response format
	var anthropicResp struct {
		Content []struct {
			Type      string `json:"type"`
			ToolUseID string `json:"tool_use_id,omitempty"`
			Content   string `json:"content,omitempty"`
			Text      string `json:"text,omitempty"`
			IsError   bool   `json:"is_error,omitempty"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &anthropicResp); err == nil {
		for _, block := range anthropicResp.Content {
			if block.Type == "tool_result" {
				results = append(results, model.ToolResult{
					ToolCallID: block.ToolUseID,
					Content:    block.Content,
					IsError:    block.IsError,
				})
			}
		}
	}

	return results
}

func (p *Proxy) writeDenyResponse(w http.ResponseWriter, decision *model.PolicyDecision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": fmt.Sprintf("GhostGuard: %s", decision.Reason),
			"type":    "policy_violation",
			"policy":  decision.PolicyName,
			"code":    "content_policy_violation",
		},
	})
}

func copyHeaders(src, dst http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
