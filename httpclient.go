package wbhttpclient

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/satori/go.uuid"
	"github.com/valyala/fasthttp"
	"github.com/wildberries-tech/wblogger"
)

type client struct {
	client  *fasthttp.Client
	host    string
	metrics httpMetrics
	timeout time.Duration
}

type Config struct {
	Name                string
	MaxIdleConnDuration time.Duration
	ReadBufferSize      int
	WriteBufferSize     int
	Host                string
	Timeout             time.Duration
}

type RequestCtx struct {
	req        *fasthttp.Request
	metricPath string
}

func New(cfg Config, metrics httpMetrics) *client {
	c := &fasthttp.Client{
		Name:                cfg.Name,
		MaxIdleConnDuration: cfg.MaxIdleConnDuration,
		ReadBufferSize:      cfg.ReadBufferSize,
		WriteBufferSize:     cfg.WriteBufferSize,
		TLSConfig:           &tls.Config{InsecureSkipVerify: true},
	}

	return &client{
		client:  c,
		host:    cfg.Host,
		metrics: metrics,
		timeout: cfg.Timeout,
	}
}

type RequestOption func(request *RequestCtx)

// WithPathTransformer applies transform to request path before writing metrics
// It's critical for preventing prometheus labels filling with dynamic paths like
// /api/v1/user/123/transaction/41234
func WithPathTransformer(transform func(path string) string) RequestOption {
	return func(req *RequestCtx) {
		req.metricPath = transform(req.metricPath)
	}
}

func WithBasicAuth(login, pass string) RequestOption {
	return func(req *RequestCtx) {
		req.req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(login+":"+pass)))
	}
}

func WithBearerAuth(token string) RequestOption {
	return func(req *RequestCtx) {
		req.req.Header.Set("Authorization", "Bearer "+token)
	}
}

func WithContentType(contentType string) RequestOption {
	return func(req *RequestCtx) {
		req.req.Header.SetContentType(contentType)
	}
}

func WithHeader(key, value string) RequestOption {
	return func(req *RequestCtx) {
		req.req.Header.Set(key, value)
	}
}

func (c *client) Get(ctx context.Context, path string, opts ...RequestOption) ([]byte, int, error) {
	return c.Do(ctx, path, fasthttp.MethodGet, nil, opts...)
}

func (c *client) Post(ctx context.Context, path string, reqObj interface{}, opts ...RequestOption) ([]byte, int, error) {
	var reqBody []byte
	var err error
	if reqObj != nil {
		reqBody, err = json.Marshal(reqObj)
		if err != nil {
			return nil, 0, fmt.Errorf("error marshal request object: %w", err)
		}
	}

	return c.Do(ctx, path, fasthttp.MethodPost, reqBody, opts...)
}

func (c *client) Put(ctx context.Context, path string, body []byte, opts ...RequestOption) ([]byte, int, error) {
	return c.Do(ctx, path, fasthttp.MethodPut, body, opts...)
}

func (c *client) Do(ctx context.Context, path string, method string, body []byte, opts ...RequestOption) ([]byte, int, error) {
	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	reqCtx := RequestCtx{
		req:        req,
		metricPath: path,
	}

	if len(body) != 0 {
		reqCtx.req.SetBody(body)
		if req.Header.ContentType() == nil || string(req.Header.ContentType()) == "" {
			reqCtx.req.Header.SetContentType("application/json")
		}
	}

	for _, f := range opts {
		f(&reqCtx)
	}

	reqId := uuid.NewV4().String()
	reqCtx.req.SetRequestURI(c.host + path)
	reqCtx.req.Header.SetMethod(method)
	wblogger.Debug(ctx, fmt.Sprintf("http-request (%s): Content-type: %s, Authorization: %s, Body: %s, URL: %s",
		reqId,
		string(reqCtx.req.Header.ContentType()),
		trimAuth(string(reqCtx.req.Header.Peek("Authorization"))),
		reqCtx.req.Body(), reqCtx.req.URI().FullURI()))

	start := time.Now()
	if err := c.client.DoDeadline(reqCtx.req, resp, deadline); err != nil {
		c.metrics.Inc(method, "0", reqCtx.metricPath)
		c.metrics.WriteTiming(start, method, "0", reqCtx.metricPath)
		return nil, 0, fmt.Errorf("error executing request: %w", err)
	}

	res := make([]byte, len(resp.Body()))
	copy(res, resp.Body())

	wblogger.Debug(ctx, fmt.Sprintf("http-response (%s): %s", reqId, resp.String()))
	if resp.StatusCode() < 300 && resp.StatusCode() >= 200 {
		c.metrics.Inc(method, strconv.Itoa(resp.StatusCode()), reqCtx.metricPath)
		c.metrics.WriteTiming(start, method, strconv.Itoa(resp.StatusCode()), reqCtx.metricPath)
		return res, resp.StatusCode(), nil
	}

	c.metrics.Inc(method, strconv.Itoa(resp.StatusCode()), reqCtx.metricPath)
	c.metrics.WriteTiming(start, method, strconv.Itoa(resp.StatusCode()), reqCtx.metricPath)
	return res,
		resp.StatusCode(),
		fmt.Errorf("http request failed with code %d host: %s body: %s", resp.StatusCode(), c.host, resp.Body())
}

func (c *client) GetObject(ctx context.Context, path string, dst interface{}, opts ...RequestOption) (int, error) {
	body, code, err := c.Do(ctx, path, fasthttp.MethodGet, nil, opts...)
	err2 := json.Unmarshal(body, dst)
	if err == nil && err2 != nil {
		err = fmt.Errorf("error unmarshal body (%s): %w", string(body), err2)
	}
	return code, err
}

func (c *client) PostObject(ctx context.Context, path string, reqObj, dst interface{}, opts ...RequestOption) (int, error) {
	reqBody, err := json.Marshal(reqObj)
	if err != nil {
		return 0, fmt.Errorf("error marshal request object: %w", err)
	}

	body, code, err := c.Do(ctx, path, fasthttp.MethodPost, reqBody, opts...)
	if err != nil {
		return code, err
	}

	if dst != nil {
		if err := json.Unmarshal(body, dst); err != nil {
			return code, fmt.Errorf("error unmarshal body (%s): %w", string(body), err)
		}
	}

	return code, nil
}

func WithHmacAuth(client, key string) RequestOption {
	return func(req *RequestCtx) {
		hmacer := hmac.New(sha256.New, []byte(key))
		hmacer.Write(req.req.Body())

		authStr := "hmac " + client + ":" + base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(hmacer.Sum(nil))))
		req.req.Header.Set("Authorization", authStr)
	}
}

func WithHmacSha256Auth(client, key string) RequestOption {
	return func(req *RequestCtx) {
		hmacer := hmac.New(sha256.New, []byte(key))
		if _, err := hmacer.Write(req.req.Body()); err != nil {
			wblogger.Error(context.Background(), "WithHmacAuth", err)
		}

		authStr := "hmac-sha256 " + client + ":" + base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(hmacer.Sum(nil))))
		req.req.Header.Set("Authorization", authStr)
	}
}

func (c *client) PostRawBody(ctx context.Context, path string, reqBody []byte, dst interface{}, opts ...RequestOption) (int, error) {
	body, code, err := c.Do(ctx, path, fasthttp.MethodPost, reqBody, opts...)
	if err != nil {
		return code, err
	}

	if dst != nil {
		if err := json.Unmarshal(body, dst); err != nil {
			return code, fmt.Errorf("error unmarshal body (%s): %w", string(body), err)
		}
	}

	return code, nil
}

func trimAuth(in string) string {
	if in == "" {
		return in
	}

	return in[:3]
}
