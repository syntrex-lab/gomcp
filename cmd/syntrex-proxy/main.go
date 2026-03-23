// syntrex-proxy — transparent reverse proxy that scans LLM prompts.
//
// Usage:
//
//	syntrex-proxy \
//	  --target https://api.openai.com \
//	  --listen :8080 \
//	  --soc-url http://localhost:9100 \
//	  --api-key sk-xxx \
//	  --mode block
//
// Supported LLM APIs:
//   - OpenAI  /v1/chat/completions
//   - Anthropic /v1/messages
//   - Ollama  /api/generate, /api/chat
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	Listen  string
	Target  string
	SocURL  string
	APIKey  string
	Mode    string // "block" or "audit"
	Verbose bool
}

// ScanResult from SOC API
type ScanResult struct {
	Verdict          string  `json:"verdict"` // ALLOW, BLOCK, WARN
	Score            float64 `json:"score"`
	Category         string  `json:"category"`
	EnginesTriggered int     `json:"engines_triggered"`
}

// extractPrompts extracts user-facing text from various LLM API formats.
func extractPrompts(body []byte, path string) []string {
	var prompts []string
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	// OpenAI: /v1/chat/completions → messages[].content
	if messages, ok := data["messages"]; ok {
		if msgs, ok := messages.([]interface{}); ok {
			for _, m := range msgs {
				if msg, ok := m.(map[string]interface{}); ok {
					if role, _ := msg["role"].(string); role == "user" {
						if content, ok := msg["content"].(string); ok && content != "" {
							prompts = append(prompts, content)
						}
					}
				}
			}
		}
	}

	// Anthropic: /v1/messages → content[].text
	if content, ok := data["content"]; ok {
		if items, ok := content.([]interface{}); ok {
			for _, item := range items {
				if c, ok := item.(map[string]interface{}); ok {
					if text, ok := c["text"].(string); ok && text != "" {
						prompts = append(prompts, text)
					}
				}
			}
		}
	}

	// Ollama: /api/generate → prompt, /api/chat → messages[].content
	if prompt, ok := data["prompt"].(string); ok && prompt != "" {
		prompts = append(prompts, prompt)
	}

	// Generic: input, query, text fields
	for _, field := range []string{"input", "query", "text", "raw_input"} {
		if val, ok := data[field].(string); ok && val != "" {
			prompts = append(prompts, val)
		}
	}

	return prompts
}

// scanPrompt sends the prompt to SOC for scanning.
func scanPrompt(socURL, apiKey, prompt string) (*ScanResult, error) {
	payload, _ := json.Marshal(map[string]interface{}{
		"source":    "syntrex-proxy",
		"category":  "proxy_scan",
		"severity":  "MEDIUM",
		"raw_input": prompt,
	})

	req, err := http.NewRequest("POST", socURL+"/api/v1/soc/events", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SOC unreachable: %w", err)
	}
	defer resp.Body.Close()

	var result ScanResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// SOC returned event, not scan result — default to ALLOW
		return &ScanResult{Verdict: "ALLOW", Score: 0, Category: "safe"}, nil
	}

	return &result, nil
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Listen, "listen", ":8080", "Listen address")
	flag.StringVar(&cfg.Target, "target", "https://api.openai.com", "Target LLM API URL")
	flag.StringVar(&cfg.SocURL, "soc-url", "http://localhost:9100", "SYNTREX SOC API URL")
	flag.StringVar(&cfg.APIKey, "api-key", "", "SYNTREX API key")
	flag.StringVar(&cfg.Mode, "mode", "block", "Mode: block (reject threats) or audit (log only)")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Verbose logging")
	flag.Parse()

	targetURL, err := url.Parse(cfg.Target)
	if err != nil {
		log.Fatalf("Invalid target URL: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	originalDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetURL.Host
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only scan POST requests to known LLM endpoints
		if r.Method != "POST" {
			proxy.ServeHTTP(w, r)
			return
		}

		// Read body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			proxy.ServeHTTP(w, r)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		// Extract prompts
		prompts := extractPrompts(body, r.URL.Path)
		if len(prompts) == 0 {
			// No prompts found — pass through
			proxy.ServeHTTP(w, r)
			return
		}

		combined := strings.Join(prompts, " ")
		start := time.Now()

		// Scan
		result, err := scanPrompt(cfg.SocURL, cfg.APIKey, combined)
		scanDuration := time.Since(start)

		if err != nil {
			log.Printf("[WARN] Scan failed (allowing): %v", err)
			proxy.ServeHTTP(w, r)
			return
		}

		if cfg.Verbose {
			log.Printf("[SCAN] %s %s → %s (score=%.2f, category=%s, %v)",
				r.Method, r.URL.Path, result.Verdict, result.Score, result.Category, scanDuration)
		}

		// Block mode
		if cfg.Mode == "block" && result.Verdict == "BLOCK" {
			log.Printf("[BLOCKED] %s %s — %s (score=%.2f, engines=%d)",
				r.Method, r.URL.Path, result.Category, result.Score, result.EnginesTriggered)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"message": fmt.Sprintf("Request blocked by SYNTREX Guard: %s (score: %.0f%%)", result.Category, result.Score*100),
					"type":    "syntrex_guard_block",
					"code":    "prompt_blocked",
				},
			})
			return
		}

		// Audit mode or ALLOW — pass through
		if result.Verdict != "ALLOW" {
			log.Printf("[AUDIT] %s %s — %s (score=%.2f)", r.Method, r.URL.Path, result.Category, result.Score)
		}
		proxy.ServeHTTP(w, r)
	})

	log.Printf("🛡️  SYNTREX Proxy starting")
	log.Printf("   Listen:  %s", cfg.Listen)
	log.Printf("   Target:  %s", cfg.Target)
	log.Printf("   SOC:     %s", cfg.SocURL)
	log.Printf("   Mode:    %s", cfg.Mode)
	log.Printf("")
	log.Printf("   Usage: set your OpenAI base_url to http://localhost%s", cfg.Listen)

	if err := http.ListenAndServe(cfg.Listen, handler); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
