package updater

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/XXXXD-cation/OpenEDR/agent/internal/config"
	"github.com/XXXXD-cation/OpenEDR/shared/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Update.UpdateServer = "https://test.example.com"

	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	upd := New(cfg, log)
	assert.NotNil(t, upd)
}

func TestCheckForUpdates_Disabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Update.Enabled = false

	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	upd := New(cfg, log)

	info, err := upd.CheckForUpdates()
	assert.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "updates are disabled")
}

func TestCheckForUpdates_NoUpdatesAvailable(t *testing.T) {
	// Create mock server that returns 204 No Content
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/api/v1/updates/agent/")
		assert.Contains(t, r.URL.Path, "/latest")
		assert.Equal(t, "GET", r.Method)

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Update.Enabled = true
	cfg.Update.UpdateServer = server.URL
	cfg.Version = "1.0.0"

	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	upd := New(cfg, log)

	info, err := upd.CheckForUpdates()
	assert.NoError(t, err)
	assert.Nil(t, info)
}

func TestCheckForUpdates_UpdateAvailable(t *testing.T) {
	updateInfo := UpdateInfo{
		Version:     "2.0.0",
		ReleaseDate: time.Now(),
		Description: "Test update",
		Critical:    false,
		DownloadURL: "https://example.com/update.tar.gz",
		Checksum:    "abc123",
		Size:        1024,
		MinVersion:  "1.0.0",
	}

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/api/v1/updates/agent/")
		assert.Equal(t, "GET", r.Method)

		// Check headers
		assert.Contains(t, r.Header.Get("User-Agent"), "OpenEDR-Agent")
		assert.Equal(t, "1.0.0", r.Header.Get("X-Current-Version"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updateInfo)
	}))
	defer server.Close()

	cfg := config.DefaultConfig()
	cfg.Update.Enabled = true
	cfg.Update.UpdateServer = server.URL
	cfg.Version = "1.0.0"

	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	upd := New(cfg, log)

	info, err := upd.CheckForUpdates()
	assert.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "2.0.0", info.Version)
	assert.Equal(t, "Test update", info.Description)
	assert.False(t, info.Critical)
	assert.Equal(t, "https://example.com/update.tar.gz", info.DownloadURL)
	assert.Equal(t, "abc123", info.Checksum)
	assert.Equal(t, int64(1024), info.Size)
}

func TestUpdateInfo_JSON(t *testing.T) {
	info := UpdateInfo{
		Version:     "1.2.3",
		ReleaseDate: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		Description: "Test update",
		Critical:    true,
		DownloadURL: "https://example.com/update.tar.gz",
		Checksum:    "abc123def456",
		Size:        2048,
		MinVersion:  "1.0.0",
	}

	// Test JSON marshaling
	data, err := json.Marshal(info)
	require.NoError(t, err)

	// Test JSON unmarshaling
	var decoded UpdateInfo
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, info.Version, decoded.Version)
	assert.Equal(t, info.Description, decoded.Description)
	assert.Equal(t, info.Critical, decoded.Critical)
	assert.Equal(t, info.DownloadURL, decoded.DownloadURL)
	assert.Equal(t, info.Checksum, decoded.Checksum)
	assert.Equal(t, info.Size, decoded.Size)
	assert.Equal(t, info.MinVersion, decoded.MinVersion)
}
