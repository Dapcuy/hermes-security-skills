// Package mcp mengimplementasikan MCP server mode (ROADMAP 4.3, 35):
// control plane yang di-expose ke Hermes sebagai Model Context Protocol
// server — JSON-RPC 2.0 line-delimited over stdio.
//
// Enforcement in-line (§4.3): setiap tool berisiko mengeksekusi policy
// check (scope + risk + approval) SEBELUM provider dipanggil, di dalam
// proses yang sama. Hermes secara teknis tidak bisa mem-bypass karena
// ini satu-satunya jalur ke provider. Semua error fail-closed.
package mcp

import (
	"encoding/json"
	"fmt"
)

// Kode error JSON-RPC 2.0 standar.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// ProtocolVersion MCP yang diumumkan saat initialize.
const ProtocolVersion = "2024-11-05"

// rpcRequest envelope JSON-RPC 2.0 masuk. ID json.RawMessage agar bisa
// membedakan notification (tanpa id) dan echo persis ke response.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// rpcError bagian "error" pada response.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("jsonrpc %d: %s", e.Code, e.Message)
}

// rpcResponse envelope keluar. Result dan Error saling eksklusif
// (result di-omit saat error — JSON-RPC 2.0).
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// errInvalidRequest, dst: constructor error standar.
func errParse(detail any) *rpcError {
	return &rpcError{Code: codeParseError, Message: "Invalid JSON was received by the server.", Data: detail}
}

func errInvalidRequest(detail any) *rpcError {
	return &rpcError{Code: codeInvalidRequest, Message: "The JSON sent is not a valid Request object.", Data: detail}
}

func errMethodNotFound(method string) *rpcError {
	return &rpcError{Code: codeMethodNotFound, Message: fmt.Sprintf("Method not found: %q", method)}
}

func errInvalidParams(detail any) *rpcError {
	return &rpcError{Code: codeInvalidParams, Message: "Invalid method parameter(s).", Data: detail}
}

func errInternal(detail any) *rpcError {
	return &rpcError{Code: codeInternalError, Message: "Internal JSON-RPC error.", Data: detail}
}
