package unboundrpz

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// DownloadHosts fetches an HTTP(S) hosts feed to a temp file.
func DownloadHosts(url string, timeout time.Duration) (path string, cleanup func(), err error) {
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "PowerSVX-unboundrpz/1.6")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.CreateTemp("", "powersvx-hosts-*.txt")
	if err != nil {
		return "", nil, err
	}
	path = f.Name()
	cleanup = func() { _ = os.Remove(path) }
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}
