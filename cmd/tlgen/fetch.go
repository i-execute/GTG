package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	tdRawBase     = "https://raw.githubusercontent.com/tdlib/td/"
	tdVersionPath = "td/telegram/Version.h"
	tdCommitURL   = "https://api.github.com/repos/tdlib/td/commits/HEAD"
	httpTimeout   = 60 * time.Second
)

func httpClient() *http.Client {
	return &http.Client{Timeout: httpTimeout}
}

func resolveLayer(target string) (string, int, error) {
	if target == "" {
		return "", 0, fmt.Errorf("gtg: empty layer target")
	}
	commit := target
	if strings.EqualFold(target, "latest") {
		fetched, err := fetchCommit()
		if err != nil {
			return "", 0, err
		}
		commit = fetched
	} else if len(target) != 40 || !isHex(target) {
		return "", 0, fmt.Errorf("gtg: layer target must be \"latest\" or a 40-character commit")
	}
	layer, err := fetchLayer(commit)
	if err != nil {
		return "", 0, err
	}
	return commit, layer, nil
}

func fetchCommit() (string, error) {
	response, err := httpClient().Get(tdCommitURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gtg: tdlib HEAD lookup status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var payload struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", err
	}
	if len(payload.SHA) != 40 || !isHex(payload.SHA) {
		return "", fmt.Errorf("gtg: tdlib HEAD lookup returned an unexpected commit")
	}
	return payload.SHA, nil
}

func fetchLayer(commit string) (int, error) {
	body, err := fetchURL(tdRawBase + commit + "/" + tdVersionPath)
	if err != nil {
		return 0, err
	}
	layer := 0
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#define MTPROTO_LAYER") {
			continue
		}
		value := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(trimmed, "#define MTPROTO_LAYER")), ";")
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("gtg: unparsable MTPROTO_LAYER %q", value)
		}
		layer = parsed
	}
	if layer <= 0 {
		return 0, fmt.Errorf("gtg: MTPROTO_LAYER not found for commit %s", commit)
	}
	return layer, nil
}

func fetchSchema(commit, name string) ([]byte, error) {
	return fetchURL(tdRawBase + commit + "/td/generate/scheme/" + name + ".tl")
}

func fetchURL(location string) ([]byte, error) {
	response, err := httpClient().Get(location)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gtg: fetch %s status %d", location, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func writeUpdatedLock(path, commit string, layer int, digests []string, names []string) error {
	var builder strings.Builder
	builder.WriteString("{\n  \"schema_revision\": \"" + commit + "\",\n  \"layer\": " + strconv.Itoa(layer) + ",\n  \"schemas\": [\n")
	for index := range names {
		builder.WriteString("    {\n      \"name\": \"" + names[index] + "\",\n      \"source\": \"https://raw.githubusercontent.com/tdlib/td/" + commit + "/td/generate/scheme/" + names[index] + ".tl\",\n      \"sha256\": \"" + digests[index] + "\"\n    }")
		if index != len(names)-1 {
			builder.WriteString(",")
		}
		builder.WriteString("\n")
	}
	builder.WriteString("  ]\n}\n")
	return os.WriteFile(path, []byte(builder.String()), 0o644)
}

func schemaDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func isHex(value string) bool {
	for _, symbol := range value {
		if (symbol < '0' || symbol > '9') && (symbol < 'a' || symbol > 'f') && (symbol < 'A' || symbol > 'F') {
			return false
		}
	}
	return true
}
