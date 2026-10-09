package crypto

import (
	"bufio"
	"context"
	"crypto/sha1"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HIBPClient checks if a password has been leaked using k-Anonymity API (Pwned Passwords).
type HIBPClient struct {
	client *http.Client
}

// NewHIBPClient creates a new client for HaveIBeenPwned checks.
func NewHIBPClient(timeout time.Duration) *HIBPClient {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &HIBPClient{
		client: &http.Client{Timeout: timeout},
	}
}

// IsPwned returns true if the password hash prefix/suffix matches in HIBP database.
func (h *HIBPClient) IsPwned(ctx context.Context, password string) (bool, int, error) {
	if password == "" {
		return false, 0, nil
	}

	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password))) // #nosec G505 -- SHA-1 is required by the HIBP k-anonymity API contract
	prefix := hash[:5]
	suffix := hash[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pwnedpasswords.com/range/"+prefix, nil)
	if err != nil {
		return false, 0, fmt.Errorf("creating HIBP request: %w", err)
	}

	req.Header.Set("User-Agent", "Auth-Service-HIBP-Checker")

	resp, err := h.client.Do(req)
	if err != nil {
		return false, 0, fmt.Errorf("calling HIBP API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("HIBP API returned status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) == 2 && parts[0] == suffix {
			count, _ := strconv.Atoi(parts[1])
			return true, count, nil
		}
	}

	return false, 0, scanner.Err()
}
