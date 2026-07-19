package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ageis/secrets-manager/internal/crypto"
)

func main() {
	serverURL := flag.String("server", "https://localhost:8443", "secrets-manager daemon URL")
	secretIDs := flag.String("secrets", "", "comma-separated secret IDs to fetch")
	principalID := flag.String("principal", "", "principal ID (CI service account)")
	privKeyPath := flag.String("privkey-file", "", "path to base64-encoded X25519 private key file")
	useStdin := flag.Bool("privkey-stdin", false, "read private key from stdin instead of file")
	cmdArgs := flag.String("cmd", "", "command to run with secrets as env vars")
	envFile := flag.String("env-file", "", "write secrets to this .env file instead of running a command")
	insecure := flag.Bool("insecure", false, "skip TLS verification (DEV ONLY — prints warning)")
	retries := flag.Int("retries", 3, "number of retry attempts on connection failure")
	retryDelay := flag.Duration("retry-delay", 2*time.Second, "delay between retries")
	jwtToken := flag.String("jwt-token", "", "JWT bearer token for authentication (alternative to mTLS)")
	jwtTokenFile := flag.String("jwt-token-file", "", "path to file containing JWT token")
	flag.Parse()

	if *secretIDs == "" || *principalID == "" {
		fmt.Fprintf(os.Stderr, "Usage: ci-client --secrets ID1,ID2 --principal ID [--privkey-file path | --privkey-stdin] [--cmd \"cmd\" | --env-file .env]\n")
		os.Exit(1)
	}
	if *cmdArgs == "" && *envFile == "" {
		fmt.Fprintf(os.Stderr, "error: specify either --cmd or --env-file\n")
		os.Exit(1)
	}
	if *cmdArgs != "" && *envFile != "" {
		fmt.Fprintf(os.Stderr, "error: specify only one of --cmd or --env-file\n")
		os.Exit(1)
	}

	if *insecure {
		fmt.Fprintln(os.Stderr, "WARNING: --insecure disables TLS certificate verification. Do NOT use in production.")
	}

	var privKey []byte
	if *useStdin {
		var err error
		privKey, err = crypto.ReadKeyFromStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read private key from stdin: %v\n", err)
			os.Exit(1)
		}
	} else if *privKeyPath != "" {
		var err error
		privKey, err = crypto.ReadKeyFromFile(*privKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load private key: %v\n", err)
			os.Exit(1)
		}
	}
	defer crypto.ZeroBytes(privKey)

	httpClient := &http.Client{Timeout: 30 * time.Second}
	if *insecure {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	authToken := resolveAuthToken(*jwtToken, *jwtTokenFile)

	secretIDsList := strings.Split(*secretIDs, ",")
	envVars := make(map[string]string)

	for _, sid := range secretIDsList {
		sid = strings.TrimSpace(sid)
		if sid == "" {
			continue
		}
		plaintext, err := fetchAndDecrypt(httpClient, *serverURL, *principalID, sid, authToken, privKey, *retries, *retryDelay)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch secret %s: %v\n", sid, err)
			os.Exit(1)
		}
		envVars[sid] = plaintext
	}

	if *envFile != "" {
		writeEnvFile(*envFile, envVars)
		return
	}

	runCommand(*cmdArgs, envVars)
}

type fetchResult struct {
	KeyName    string
	Ciphertext string
	Nonce      string
	WrappedDEK string
}

func fetchAndDecrypt(client *http.Client, serverURL, principalID, secretID, token string, privKey []byte, maxRetries int, delay time.Duration) (string, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(delay)
		}
		result, err := fetchSecret(client, serverURL, principalID, secretID, token)
		if err == nil {
			return decryptResult(result, privKey)
		}
		lastErr = err
	}
	return "", fmt.Errorf("after %d retries: %w", maxRetries, lastErr)
}

func decryptResult(result *fetchResult, privKey []byte) (string, error) {
	wrappedDEK, err := crypto.B64Decode(result.WrappedDEK)
	if err != nil {
		return "", fmt.Errorf("decode wrapped DEK: %w", err)
	}
	dek, err := crypto.UnwrapDEK(wrappedDEK, privKey)
	if err != nil {
		return "", fmt.Errorf("unwrap DEK: %w", err)
	}
	defer crypto.ZeroBytes(dek)

	ct, err := crypto.B64Decode(result.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	nonce, err := crypto.B64Decode(result.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}
	plaintext, err := crypto.DecryptGCM(dek, ct, nonce, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	val := string(plaintext)
	crypto.ZeroBytes(plaintext)
	return val, nil
}

func fetchSecret(client *http.Client, serverURL, principalID, secretID, token string) (*fetchResult, error) {
	body, err := json.Marshal(map[string]string{"secret_id": secretID})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", serverURL+"/api/v1/fetch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("daemon error (%d): %s", resp.StatusCode, string(b))
	}

	var result struct {
		KeyName    string `json:"key_name"`
		Ciphertext string `json:"ciphertext"`
		Nonce      string `json:"nonce"`
		WrappedDEK string `json:"wrapped_dek"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &fetchResult{
		KeyName:   result.KeyName,
		Ciphertext: result.Ciphertext,
		Nonce:      result.Nonce,
		WrappedDEK: result.WrappedDEK,
	}, nil
}

func resolveAuthToken(token, tokenFile string) string {
	if token != "" {
		return token
	}
	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read JWT token file: %v\n", err)
			os.Exit(1)
		}
		var parsed struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return strings.TrimSpace(string(data))
		}
		return parsed.Token
	}
	return ""
}

func writeEnvFile(path string, envVars map[string]string) {
	var buf bytes.Buffer
	for k, v := range envVars {
		buf.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	}
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write env file: %v\n", err)
		os.Exit(1)
	}
}

func runCommand(cmdStr string, envVars map[string]string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", cmdStr)
	} else {
		cmd = exec.Command("sh", "-c", cmdStr)
	}

	cmd.Env = append(os.Environ())
	for k, v := range envVars {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}
}
