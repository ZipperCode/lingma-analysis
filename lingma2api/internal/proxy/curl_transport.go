package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type CurlTransport struct {
	baseURL string
	signer  *SignatureEngine
	timeout time.Duration
}

type curlStream struct {
	reader  *bufio.Reader
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	cmd     *exec.Cmd
	once    sync.Once
	waitErr error
}

func NewCurlTransport(baseURL string, signer *SignatureEngine, timeout time.Duration) *CurlTransport {
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	return &CurlTransport{
		baseURL: strings.TrimRight(baseURL, "/"),
		signer:  signer,
		timeout: timeout,
	}
}

func (transport *CurlTransport) ListModels(ctx context.Context, credential CredentialSnapshot) ([]RemoteModel, error) {
	headers, err := transport.signer.BuildHeaders(ctx, credential, ModelListPath, "")
	if err != nil {
		return nil, err
	}

	args := buildCurlArgs(headers, "", transport.baseURL+ModelListPath, false, transport.timeout)
	output, err := exec.CommandContext(ctx, "curl", args...).CombinedOutput()
	if err != nil && len(output) == 0 {
		return nil, err
	}

	statusCode, body, err := parseCurlResponse(output)
	if err != nil {
		return nil, err
	}
	if statusCode >= 400 {
		return nil, &UpstreamHTTPError{StatusCode: statusCode, Body: strings.TrimSpace(string(body))}
	}

	var payload struct {
		Chat   []RemoteModel `json:"chat"`
		Inline []RemoteModel `json:"inline"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return append(payload.Chat, payload.Inline...), nil
}

func (transport *CurlTransport) StreamChat(ctx context.Context, request RemoteChatRequest, credential CredentialSnapshot) (io.ReadCloser, error) {
	headers, err := transport.signer.BuildHeaders(ctx, credential, request.Path, request.BodyJSON)
	if err != nil {
		return nil, err
	}

	args := buildCurlArgs(headers, request.BodyJSON, transport.baseURL+request.Path+request.Query, true, transport.timeout)
	cmd := exec.CommandContext(ctx, "curl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(stdout)
	statusCode, err := readHeaderStatus(reader)
	if err != nil {
		_ = cmd.Wait()
		return nil, err
	}
	if statusCode >= 400 {
		bodyBytes, _ := io.ReadAll(reader)
		stderrBytes, _ := io.ReadAll(stderr)
		_ = cmd.Wait()
		return nil, &UpstreamHTTPError{
			StatusCode: statusCode,
			Body:       strings.TrimSpace(string(bodyBytes) + " " + string(stderrBytes)),
		}
	}

	return &curlStream{
		reader: reader,
		stdout: stdout,
		stderr: stderr,
		cmd:    cmd,
	}, nil
}

func buildCurlArgs(headers map[string]string, body, url string, streaming bool, timeout time.Duration) []string {
	args := []string{
		"-sS",
		"-D", "-",
		"--max-time", strconv.Itoa(timeoutSeconds(timeout)),
	}
	if streaming {
		args = append(args, "-N")
	}

	headerKeys := make([]string, 0, len(headers))
	for key := range headers {
		headerKeys = append(headerKeys, key)
	}
	for _, key := range headerKeys {
		args = append(args, "-H", key+": "+headers[key])
	}
	if body != "" {
		args = append(args, "-d", body)
	}
	args = append(args, url)
	return args
}

func parseCurlResponse(raw []byte) (int, []byte, error) {
	separator := []byte("\r\n\r\n")
	index := bytes.Index(raw, separator)
	width := len(separator)
	if index < 0 {
		separator = []byte("\n\n")
		index = bytes.Index(raw, separator)
		width = len(separator)
	}
	if index < 0 {
		return 0, nil, fmt.Errorf("missing header separator")
	}

	statusCode, err := parseStatusCode(string(bytes.SplitN(raw[:index], []byte("\n"), 2)[0]))
	if err != nil {
		return 0, nil, err
	}
	return statusCode, raw[index+width:], nil
}

func readHeaderStatus(reader *bufio.Reader) (int, error) {
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	statusCode, err := parseStatusCode(statusLine)
	if err != nil {
		return 0, err
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		if strings.TrimSpace(line) == "" {
			return statusCode, nil
		}
	}
}

func parseStatusCode(line string) (int, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return 0, fmt.Errorf("invalid status line %q", line)
	}
	return strconv.Atoi(fields[1])
}

func timeoutSeconds(timeout time.Duration) int {
	if timeout <= 0 {
		return 1
	}
	seconds := int(timeout / time.Second)
	if seconds <= 0 {
		return 1
	}
	return seconds
}

func (stream *curlStream) Read(data []byte) (int, error) {
	n, err := stream.reader.Read(data)
	if err == io.EOF {
		stream.wait()
	}
	return n, err
}

func (stream *curlStream) Close() error {
	_ = stream.stdout.Close()
	stream.wait()
	return stream.waitErr
}

func (stream *curlStream) wait() {
	stream.once.Do(func() {
		stderrBytes, _ := io.ReadAll(stream.stderr)
		err := stream.cmd.Wait()
		if err != nil && len(stderrBytes) > 0 {
			stream.waitErr = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(stderrBytes)))
			return
		}
		stream.waitErr = err
	})
}
