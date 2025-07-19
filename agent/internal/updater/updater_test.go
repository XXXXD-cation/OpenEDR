package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

func TestUpdater_PathValidation(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Update.Enabled = true

	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	upd := New(cfg, log)

	// Test dangerous paths for checksum verification
	dangerousPaths := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\config\\sam",
		"/etc/shadow",
		"/root/.ssh/id_rsa",
	}

	for _, path := range dangerousPaths {
		t.Run("dangerous_checksum_path_"+path, func(t *testing.T) {
			err := upd.verifyChecksum(path, "dummy_checksum")
			// Should fail due to path validation
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "unauthorized file path")
		})
	}

	// Test dangerous paths for package extraction
	for _, path := range dangerousPaths {
		t.Run("dangerous_extract_path_"+path, func(t *testing.T) {
			err := upd.extractPackage(path, "/tmp")
			// Should fail due to path validation
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "unauthorized package path")
		})
	}
}

func TestUpdater_ArchiveExtractionSecurity(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Update.Enabled = true

	log, err := logger.New(logger.LogConfig{Level: "debug"})
	require.NoError(t, err)
	defer log.Close()

	upd := New(cfg, log)

	t.Run("malicious_archive_paths", func(t *testing.T) {
		// Test that malicious archive paths are rejected
		maliciousPaths := []string{
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"../../../../root/.ssh/id_rsa",
			"dir/../../../etc/shadow",
		}

		for _, maliciousPath := range maliciousPaths {
			// Create a mock tar.gz with malicious path
			// This would be caught by ValidateArchiveEntry in the actual extraction
			t.Run("path_"+maliciousPath, func(t *testing.T) {
				// The security validation should catch this in ValidateArchiveEntry
				// which is called from extractTarGz
				tempDir := t.TempDir()
				err := upd.extractTarGz(createMaliciousTarGz(t, maliciousPath), tempDir)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "malicious archive entry detected")
			})
		}
	})

	t.Run("archive_size_limits", func(t *testing.T) {
		// Test that archives exceeding size limits are rejected
		tempDir := t.TempDir()

		// This would create an archive that exceeds the file size limit
		// The actual implementation would catch this in ValidateArchiveEntry
		largeTarGz := createLargeTarGz(t, 100*1024*1024) // 100MB file
		err := upd.extractTarGz(largeTarGz, tempDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "malicious archive entry detected")
	})

	t.Run("archive_depth_limits", func(t *testing.T) {
		// Test that archives with excessive directory depth are rejected
		tempDir := t.TempDir()

		// Create path with excessive depth
		deepPath := "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/file.txt"
		deepTarGz := createMaliciousTarGz(t, deepPath)
		err := upd.extractTarGz(deepTarGz, tempDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "malicious archive entry detected")
	})
}

// Helper function to create a malicious tar.gz for testing
func createMaliciousTarGz(t *testing.T, maliciousPath string) *bytes.Reader {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Create a tar entry with malicious path
	header := &tar.Header{
		Name:     maliciousPath,
		Mode:     0644,
		Size:     10,
		Typeflag: tar.TypeReg,
	}

	err := tw.WriteHeader(header)
	require.NoError(t, err)

	_, err = tw.Write([]byte("test data\n"))
	require.NoError(t, err)

	err = tw.Close()
	require.NoError(t, err)

	err = gw.Close()
	require.NoError(t, err)

	return bytes.NewReader(buf.Bytes())
}

// Helper function to create a large tar.gz for testing
func createLargeTarGz(t *testing.T, size int64) *bytes.Reader {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Create a tar entry with large size
	header := &tar.Header{
		Name:     "large_file.txt",
		Mode:     0644,
		Size:     size,
		Typeflag: tar.TypeReg,
	}

	err := tw.WriteHeader(header)
	require.NoError(t, err)

	// Write the full size to match the header
	data := make([]byte, 1024)
	for i := 0; i < len(data); i++ {
		data[i] = byte(i % 256)
	}

	remaining := size
	for remaining > 0 {
		writeSize := int64(len(data))
		if remaining < writeSize {
			writeSize = remaining
		}
		_, err = tw.Write(data[:writeSize])
		require.NoError(t, err)
		remaining -= writeSize
	}

	err = tw.Close()
	require.NoError(t, err)

	err = gw.Close()
	require.NoError(t, err)

	return bytes.NewReader(buf.Bytes())
}
