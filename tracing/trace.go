package tracing

import (
	"context"
	"net/http"
)

var (
	traceHeaderKey = traceHeader("trace_header")
	traceIDKey     = traceID("trace_header")
)

type traceHeader string
type traceID string

func ContextWithTraceID(parent context.Context, traceHeader, traceID string) context.Context {
	ctx := context.WithValue(parent, traceHeaderKey, traceHeader)
	return context.WithValue(ctx, traceIDKey, traceID)
}

func AddTraceIDFromContext(ctx context.Context, req *http.Request) {
	header := GetContextKey(ctx, traceHeaderKey)
	traceId := GetContextKey(ctx, traceIDKey)

	if header == "" || traceId == "" {
		return
	}

	req.Header.Set(header, traceId)
}

func GetContextKey(ctx context.Context, key any) string {
	val := ""
	if v := ctx.Value(key); v != nil {
		val = v.(string)
	}
	return val
}