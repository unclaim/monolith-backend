package user

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"

	"log/slog"
)

const debugMode = true

func handleError(w http.ResponseWriter, req *http.Request, err error, statusCode int) {
	ipAddress := getClientIP(req)
	slog.Error(
		"API Error occurred",
		slog.String("error", err.Error()),
		slog.String("method", req.Method),
		slog.String("path", req.URL.Path),
		slog.String("remote_ip", ipAddress),
	)
	var trace []byte
	if debugMode {
		trace = debug.Stack()
	}

	errorResp := &ErrorResponse{
		ErrorMessage: fmt.Sprintf("%s", err),
		ErrorType:    determineErrorType(statusCode),
		StackTrace:   formatStackTrace(trace), // Красиво оформляем стектрейс
	}

	response := &Response{
		StatusCode: statusCode,
		Body:       errorResp,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return
	}
}
func getClientIP(r *http.Request) string {
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	forwardIP := r.Header.Get("X-Forwarded-For")
	if forwardIP != "" {
		return forwardIP
	}
	addrParts := strings.Split(r.RemoteAddr, ":")
	if len(addrParts) > 0 {
		return addrParts[0]
	}

	return "unknown"
}
func formatStackTrace(trace []byte) []string {
	if len(trace) == 0 {
		return nil
	}
	lines := bytes.Split(trace, []byte("\n"))
	maxLines := 10
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	filteredLines := filterRelevantLines(lines)
	return filteredLines
}
func filterRelevantLines(lines [][]byte) []string {
	result := make([]string, 0)
	for _, line := range lines {
		str := string(line)
		if containsImportant(str) {
			formatted := formatStackFrame(str)
			result = append(result, formatted)
		}
	}

	return result
}

func containsImportant(line string) bool {
	if strings.HasPrefix(line, "goroutine ") || strings.HasSuffix(line, "+0x5e") {
		return false
	}
	return strings.Contains(line, "\t")
}
func formatStackFrame(frame string) string {
	parts := strings.Split(frame, "\t")
	if len(parts) < 2 {
		return frame
	}
	functionInfo := strings.TrimSpace(parts[0])
	locationInfo := strings.TrimSpace(parts[1])
	cleanLocation := cleanFilePath(locationInfo)
	return functionInfo + " (" + cleanLocation + ")"
}
func cleanFilePath(path string) string {
	const projectBase = "the_server_part/git/pkg/"
	if index := strings.Index(path, projectBase); index >= 0 {
		return path[index+len(projectBase):]
	}
	return path
}
func determineErrorType(statusCode int) string {
	switch statusCode {
	case http.StatusNotFound:
		return "NotFound"
	case http.StatusBadRequest:
		return "BadRequest"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusConflict:
		return "Conflict"
	case http.StatusGone:
		return "Gone"
	case http.StatusPreconditionFailed:
		return "PreconditionFailed"
	case http.StatusUnprocessableEntity:
		return "UnprocessableEntity"
	case http.StatusLocked:
		return "Locked"
	case http.StatusTooManyRequests:
		return "TooManyRequests"
	case http.StatusServiceUnavailable:
		return "ServiceUnavailable"
	case http.StatusGatewayTimeout:
		return "GatewayTimeout"
	case http.StatusMethodNotAllowed:
		return "MethodNotAllowed"
	case http.StatusInternalServerError:
		fallthrough
	case http.StatusBadGateway:
		fallthrough
	case http.StatusHTTPVersionNotSupported:
		return "InternalServerError"
	default:
		return "UnknownError"
	}
}
