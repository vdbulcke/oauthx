package tracing

import (
	"context"
	"net/http"
)

var (
	traceHeaderKey = traceHeader("trace_header")
	traceIDKey     = traceID("trace_header")
	extraHeaderKey = extraHeader("extra_headers")
)

type traceHeader string
type traceID string
type extraHeader string

// ContextWithTraceID creates a new context from parent, and adds
// tracing 'traceHeader' and 'traceID' in context values
//
// when passing this tracing context (or a children) http requests
// will automatically add "'traceHeader': 'traceId'" in request headers
func ContextWithTraceID(parent context.Context, traceHeader, traceID string) context.Context {
	ctx := context.WithValue(parent, traceHeaderKey, traceHeader)
	return context.WithValue(ctx, traceIDKey, traceID)
}

// ContextWithExtraHeader creates a new context from parent, and adds
// extra headers key/value pair that will be added to http request using this
// new context
func ContextWithExtraHeader(parent context.Context, extraHeader map[string]string) context.Context {
	return context.WithValue(parent, extraHeaderKey, extraHeader)
}

func AddHeadersFromContext(ctx context.Context, req *http.Request) {
	header := GetContextKey(ctx, traceHeaderKey)
	traceId := GetContextKey(ctx, traceIDKey)

	extraHeaders := getExtraHeaders(ctx)

	if header != "" && traceId != "" {
		extraHeaders[header] = traceId
	}

	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
}

func GetContextKey(ctx context.Context, key any) string {
	val := ""
	if v := ctx.Value(key); v != nil {
		val = v.(string)
	}
	return val
}

func getExtraHeaders(ctx context.Context) map[string]string {
	val := make(map[string]string)
	if v := ctx.Value(extraHeaderKey); v != nil {
		val = v.(map[string]string)
	}
	return val
}
