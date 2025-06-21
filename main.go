// main.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const sqlmapPath = "./sqlmap/sqlmap.py"

type ScanBatchInput struct {
	Threads   int         `json:"threads"`
	Level     int         `json:"level"`
	Risk      int         `json:"risk"`
	TimeBased bool        `json:"time_based"`
	URL       []ScanInput `json:"url"`
}

type ScanInput struct {
	URL        string            `json:"url"`
	HTTPMethod string            `json:"http_method"`
	FormParams string            `json:"form_params"`
	BodyParams string            `json:"body_params"`
	Headers    map[string]string `json:"headers"`
}

type ScanResult struct {
	ID         string `json:"id"`
	URL        string `json:"url"`
	Vulnerable bool   `json:"vulnerable"`
	Payload    string `json:"payload"`
	Status     string `json:"status"`
}

var (
	scanResults = make(map[string]*ScanResult)
	mu          sync.RWMutex
	scanCancel = make(map[string]chan struct{})
)

func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	r.POST("/acm/v1/sqlmap", handleSQLiScan)
	r.GET("/acm/v1/sqlmap/:id/status", handleStatus)
	r.GET("/acm/v1/sqlmap/:id/result", handleResult)
	r.GET("/acm/v1/sqlmap", listAllScans)
	r.DELETE("/acm/v1/sqlmap/:id", cancelScan)

	r.Run(":8080")
}

func handleSQLiScan(c *gin.Context) {
	var batchInput ScanBatchInput
	if err := c.ShouldBindJSON(&batchInput); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var results []ScanResult
	for _, input := range batchInput.URL {
		id := uuid.New().String()
		result := &ScanResult{
			ID:     id,
			URL:    input.URL,
			Status: "running",
		}
		mu.Lock()
		scanResults[id] = result
		cancelChan := make(chan struct{})
		scanCancel[id] = cancelChan
		mu.Unlock()

		go func(input ScanInput, id string, cancelChan chan struct{}) {
			res := processInputWithCancel(input, cancelChan, batchInput.Level, batchInput.Risk, batchInput.Threads, batchInput.TimeBased)
			mu.Lock()
			res.ID = id
			if res.Status != "cancelled" {
				res.Status = "done"
			}
			scanResults[id] = &res
			mu.Unlock()
		}(input, id, cancelChan)

		results = append(results, *result)
	}

	c.JSON(http.StatusAccepted, results)
}

func handleStatus(c *gin.Context) {
	id := c.Param("id")
	mu.RLock()
	res, ok := scanResults[id]
	mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan ID not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": res.Status})
}

func handleResult(c *gin.Context) {
	id := c.Param("id")
	mu.RLock()
	res, ok := scanResults[id]
	mu.RUnlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan ID not found"})
		return
	}
	if res.Status != "done" && res.Status != "cancelled" {
		c.JSON(http.StatusOK, gin.H{"status": res.Status})
		return
	}
	c.JSON(http.StatusOK, res)
}

func listAllScans(c *gin.Context) {
	mu.RLock()
	defer mu.RUnlock()
	list := make([]*ScanResult, 0, len(scanResults))
	for _, res := range scanResults {
		list = append(list, res)
	}
	c.JSON(http.StatusOK, list)
}

func cancelScan(c *gin.Context) {
	id := c.Param("id")
	mu.Lock()
	cancelChan, exists := scanCancel[id]
	if exists {
		close(cancelChan)
		delete(scanCancel, id)
		if res, ok := scanResults[id]; ok {
			res.Status = "cancelled"
		}
		mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
	} else {
		mu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan ID not found or already finished"})
	}
}

func processInputWithCancel(input ScanInput, cancelChan chan struct{}, level, risk, threads int, timeBased bool) ScanResult {
	var cmd *exec.Cmd
	url := input.URL
	var data string
	var headers []string

	for k, v := range input.Headers {
		headers = append(headers, fmt.Sprintf("%s: %s", k, v))
	}

	headerArgs := []string{}
	for _, h := range headers {
		headerArgs = append(headerArgs, "--headers="+h)
	}

	tech := "--technique=BEUSQ"
	if timeBased {
		tech = "--technique=BEUSTQ"
	}

	extraArgs := []string{
		"--batch",
		"--stop",
		fmt.Sprintf("--level=%d", level),
		fmt.Sprintf("--risk=%d", risk),
		fmt.Sprintf("--threads=%d", threads),
		tech,
		"--method=" + strings.ToUpper(input.HTTPMethod),
	}

	if input.BodyParams != "" {
		data = buildJSONData(input.BodyParams)
		headerArgs = append(headerArgs, "--headers=Content-Type: application/json")
	} else if input.FormParams != "" {
		data = buildFormData(input.FormParams)
	}

	if data == "" && !strings.Contains(url, "FUZZ") {
		return ScanResult{URL: input.URL, Vulnerable: false, Payload: "", Status: "skipped"}
	}

	if strings.Contains(url, "FUZZ") {
		url = strings.Replace(url, "FUZZ", "1*", 1)
	}

	args := []string{"-u", url}
	if data != "" {
		args = append(args, "--data", data)
	}
	args = append(args, extraArgs...)
	args = append(args, headerArgs...)

	cmd = exec.Command("python3", append([]string{sqlmapPath}, args...)...)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	done := make(chan struct{})
	go func() {
		fmt.Println("[SQLMAP CMD]", strings.Join(cmd.Args, " "))
		cmd.Run()
		fmt.Println(out.String())
		done <- struct{}{}
	}()

	select {
	case <-cancelChan:
		_ = cmd.Process.Kill()
		return ScanResult{URL: input.URL, Vulnerable: false, Payload: "", Status: "cancelled"}
	case <-done:
		payload := extractPayload(out.String())
		return ScanResult{
			URL:        input.URL,
			Vulnerable: payload != "",
			Payload:    payload,
			Status:     "done",
		}
	}
}

func buildFormData(params string) string {
	parts := strings.Split(params, ",")
	var builder strings.Builder
	for i, p := range parts {
		if i > 0 {
			builder.WriteString("&")
		}
		if i == 0 {
			builder.WriteString(fmt.Sprintf("%s=1*", strings.TrimSpace(p)))
		} else {
			builder.WriteString(fmt.Sprintf("%s=test", strings.TrimSpace(p)))
		}
	}
	return builder.String()
}

func buildJSONData(params string) string {
	parts := strings.Split(params, ",")
	m := make(map[string]string)
	for i, p := range parts {
		key := strings.TrimSpace(p)
		if i == 0 {
			m[key] = "1*"
		} else {
			m[key] = "test"
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func extractPayload(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Payload:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Payload:"))
		}
	}
	return ""
}
