package updater

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/XXXXD-cation/OpenEDR/agent/internal/config"
	"github.com/XXXXD-cation/OpenEDR/shared/logger"
	"github.com/XXXXD-cation/OpenEDR/shared/security"
)

// Updater handles agent updates
type Updater struct {
	config  *config.Config
	logger  logger.Logger
	client  *http.Client
	baseURL string
}

// UpdateInfo represents update information
type UpdateInfo struct {
	Version     string    `json:"version"`
	ReleaseDate time.Time `json:"release_date"`
	Description string    `json:"description"`
	Critical    bool      `json:"critical"`
	DownloadURL string    `json:"download_url"`
	Checksum    string    `json:"checksum"`
	Size        int64     `json:"size"`
	MinVersion  string    `json:"min_version"`
}

// UpdateStatus represents the update status
type UpdateStatus struct {
	Available        bool
	CurrentVersion   string
	LatestVersion    string
	UpdateInfo       *UpdateInfo
	LastCheckTime    time.Time
	LastUpdateTime   time.Time
	UpdateInProgress bool
}

// New creates a new updater instance
func New(cfg *config.Config, logger logger.Logger) *Updater {
	return &Updater{
		config:  cfg,
		logger:  logger,
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: cfg.Update.UpdateServer,
	}
}

// CheckForUpdates checks for available updates
func (u *Updater) CheckForUpdates() (*UpdateInfo, error) {
	if !u.config.Update.Enabled {
		return nil, fmt.Errorf("updates are disabled")
	}

	u.logger.Info("Checking for updates...")

	// Build update check URL
	platform := fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH)
	url := fmt.Sprintf("%s/api/v1/updates/agent/%s/latest", u.baseURL, platform)

	// Make request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", fmt.Sprintf("OpenEDR-Agent/%s", u.config.Version))
	req.Header.Set("X-Current-Version", u.config.Version)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		u.logger.Info("No updates available")
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update check failed with status: %d", resp.StatusCode)
	}

	// Parse response
	var updateInfo UpdateInfo
	if err := json.NewDecoder(resp.Body).Decode(&updateInfo); err != nil {
		return nil, fmt.Errorf("failed to parse update info: %w", err)
	}

	// Check if update is applicable
	if !u.isUpdateApplicable(&updateInfo) {
		u.logger.Info("Update available but not applicable: %s", updateInfo.Version)
		return nil, nil
	}

	u.logger.Info("Update available: %s", updateInfo.Version)
	return &updateInfo, nil
}

// isUpdateApplicable checks if an update can be applied
func (u *Updater) isUpdateApplicable(info *UpdateInfo) bool {
	// Check version
	if info.Version <= u.config.Version {
		return false
	}

	// Check minimum version requirement
	if info.MinVersion != "" && u.config.Version < info.MinVersion {
		u.logger.Warn("Current version %s is below minimum required version %s",
			u.config.Version, info.MinVersion)
		return false
	}

	return true
}

// DownloadUpdate downloads the update package
func (u *Updater) DownloadUpdate(info *UpdateInfo) (string, error) {
	u.logger.Info("Downloading update %s...", info.Version)

	// Create temp directory
	tempDir := filepath.Join(os.TempDir(), "openedr-update", info.Version)
	if err := os.MkdirAll(tempDir, 0750); err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Download file
	filename := filepath.Base(info.DownloadURL)
	targetPath := filepath.Join(tempDir, filename)

	// Validate target path for security
	allowedDirs := []string{
		os.TempDir(),
		filepath.Join(os.TempDir(), "openedr-update"),
	}

	if err := security.ValidatePath(targetPath, allowedDirs); err != nil {
		// Log security event
		event := security.NewSecurityEvent(
			security.UnauthorizedFileAccess,
			security.SeverityHigh,
			"updater",
			"Attempted to create file in unauthorized location",
		).AddDetail("path", targetPath).
			AddDetail("allowed_dirs", allowedDirs).
			SetRemediation("Ensure update files are only created in authorized directories")

		if eventJSON, jsonErr := event.ToJSON(); jsonErr == nil {
			u.logger.Warn("Security event: %s", string(eventJSON))
		}

		return "", fmt.Errorf("unauthorized file path for update: %w", err)
	}

	out, err := os.Create(targetPath)
	if err != nil {
		// Log security event for file creation failure
		event := security.NewSecurityEvent(
			security.UnauthorizedFileAccess,
			security.SeverityMedium,
			"updater",
			"Failed to create update file",
		).AddDetail("path", targetPath).
			AddDetail("error", err.Error()).
			SetRemediation("Check file permissions and path validity")

		if eventJSON, jsonErr := event.ToJSON(); jsonErr == nil {
			u.logger.Warn("Security event: %s", string(eventJSON))
		}

		return "", fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	resp, err := u.client.Get(info.DownloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download update: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Copy with progress
	written, err := u.copyWithProgress(out, resp.Body, info.Size)
	if err != nil {
		return "", fmt.Errorf("failed to save update: %w", err)
	}

	u.logger.Info("Downloaded %d bytes", written)

	// Verify checksum
	if err := u.verifyChecksum(targetPath, info.Checksum); err != nil {
		if removeErr := os.Remove(targetPath); removeErr != nil {
			u.logger.Error("Error removing invalid file: %v", removeErr)
		}
		return "", fmt.Errorf("checksum verification failed: %w", err)
	}

	return targetPath, nil
}

// copyWithProgress copies data with progress reporting
func (u *Updater) copyWithProgress(dst io.Writer, src io.Reader, total int64) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	lastReport := time.Now()

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = fmt.Errorf("invalid write result")
				}
			}
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}

			// Report progress
			if time.Since(lastReport) > time.Second {
				progress := float64(written) / float64(total) * 100
				u.logger.Debug("Download progress: %.1f%%", progress)
				lastReport = time.Now()
			}
		}
		if er != nil {
			if er != io.EOF {
				return written, er
			}
			break
		}
	}
	return written, nil
}

// verifyChecksum verifies file checksum
func (u *Updater) verifyChecksum(filename, expectedChecksum string) error {
	// Validate file path for security
	allowedDirs := []string{
		os.TempDir(),
		filepath.Join(os.TempDir(), "openedr-update"),
	}

	if err := security.ValidatePath(filename, allowedDirs); err != nil {
		// Log security event
		event := security.NewSecurityEvent(
			security.UnauthorizedFileAccess,
			security.SeverityHigh,
			"updater",
			"Attempted to verify checksum of file in unauthorized location",
		).AddDetail("path", filename).
			AddDetail("allowed_dirs", allowedDirs).
			SetRemediation("Ensure checksum verification is only performed on authorized files")

		if eventJSON, jsonErr := event.ToJSON(); jsonErr == nil {
			u.logger.Warn("Security event: %s", string(eventJSON))
		}

		return fmt.Errorf("unauthorized file path for checksum verification: %w", err)
	}

	file, err := os.Open(filename)
	if err != nil {
		// Log security event for file access failure
		event := security.NewSecurityEvent(
			security.UnauthorizedFileAccess,
			security.SeverityMedium,
			"updater",
			"Failed to open file for checksum verification",
		).AddDetail("path", filename).
			AddDetail("error", err.Error()).
			SetRemediation("Check file permissions and path validity")

		if eventJSON, jsonErr := event.ToJSON(); jsonErr == nil {
			u.logger.Warn("Security event: %s", string(eventJSON))
		}

		return err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	actualChecksum := fmt.Sprintf("%x", hash.Sum(nil))
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s",
			expectedChecksum, actualChecksum)
	}

	return nil
}

// ApplyUpdate applies the downloaded update
func (u *Updater) ApplyUpdate(packagePath string) error {
	u.logger.Info("Applying update from %s", packagePath)

	// Extract update package
	extractDir := filepath.Dir(packagePath)
	if err := u.extractPackage(packagePath, extractDir); err != nil {
		return fmt.Errorf("failed to extract update: %w", err)
	}

	// Find update script
	updateScript := filepath.Join(extractDir, "update.sh")
	if runtime.GOOS == "windows" {
		updateScript = filepath.Join(extractDir, "update.bat")
	}

	// Check if update script exists
	if _, err := os.Stat(updateScript); os.IsNotExist(err) {
		return fmt.Errorf("update script not found")
	}

	// Create update marker
	markerFile := filepath.Join(extractDir, "update.marker")

	// Validate marker file path for security
	allowedDirs := []string{
		os.TempDir(),
		filepath.Join(os.TempDir(), "openedr-update"),
	}

	if err := security.ValidatePath(markerFile, allowedDirs); err != nil {
		// Log security event
		event := security.NewSecurityEvent(
			security.UnauthorizedFileAccess,
			security.SeverityHigh,
			"updater",
			"Attempted to create update marker in unauthorized location",
		).AddDetail("path", markerFile).
			AddDetail("allowed_dirs", allowedDirs).
			SetRemediation("Ensure update markers are only created in authorized directories")

		if eventJSON, jsonErr := event.ToJSON(); jsonErr == nil {
			u.logger.Warn("Security event: %s", string(eventJSON))
		}

		return fmt.Errorf("unauthorized file path for update marker: %w", err)
	}

	marker := map[string]interface{}{
		"timestamp": time.Now(),
		"version":   u.config.Version,
		"pid":       os.Getpid(),
	}

	markerData, _ := json.Marshal(marker)
	if err := os.WriteFile(markerFile, markerData, 0600); err != nil {
		// Log security event for file write failure
		event := security.NewSecurityEvent(
			security.UnauthorizedFileAccess,
			security.SeverityMedium,
			"updater",
			"Failed to create update marker file",
		).AddDetail("path", markerFile).
			AddDetail("error", err.Error()).
			SetRemediation("Check file permissions and path validity")

		if eventJSON, jsonErr := event.ToJSON(); jsonErr == nil {
			u.logger.Warn("Security event: %s", string(eventJSON))
		}

		return fmt.Errorf("failed to create update marker: %w", err)
	}

	u.logger.Info("Update package prepared, restart required")

	// The actual update will be performed by the update script
	// after the agent restarts
	return nil
}

// extractPackage extracts the update package
func (u *Updater) extractPackage(packagePath, targetDir string) error {
	// Validate package path for security
	allowedDirs := []string{
		os.TempDir(),
		filepath.Join(os.TempDir(), "openedr-update"),
	}

	if err := security.ValidatePath(packagePath, allowedDirs); err != nil {
		// Log security event
		event := security.NewSecurityEvent(
			security.UnauthorizedFileAccess,
			security.SeverityHigh,
			"updater",
			"Attempted to extract package from unauthorized location",
		).AddDetail("path", packagePath).
			AddDetail("allowed_dirs", allowedDirs).
			SetRemediation("Ensure packages are only extracted from authorized directories")

		if eventJSON, jsonErr := event.ToJSON(); jsonErr == nil {
			u.logger.Warn("Security event: %s", string(eventJSON))
		}

		return fmt.Errorf("unauthorized package path for extraction: %w", err)
	}

	file, err := os.Open(packagePath)
	if err != nil {
		// Log security event for file access failure
		event := security.NewSecurityEvent(
			security.UnauthorizedFileAccess,
			security.SeverityMedium,
			"updater",
			"Failed to open package file for extraction",
		).AddDetail("path", packagePath).
			AddDetail("error", err.Error()).
			SetRemediation("Check file permissions and path validity")

		if eventJSON, jsonErr := event.ToJSON(); jsonErr == nil {
			u.logger.Warn("Security event: %s", string(eventJSON))
		}

		return err
	}
	defer file.Close()

	// Check if it's a tar.gz
	if strings.HasSuffix(packagePath, ".tar.gz") || strings.HasSuffix(packagePath, ".tgz") {
		return u.extractTarGz(file, targetDir)
	}

	return fmt.Errorf("unsupported package format")
}

// extractTarGz extracts a tar.gz archive with comprehensive security checks
func (u *Updater) extractTarGz(r io.Reader, targetDir string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	// Create extraction tracker with limits for update packages
	limits := security.ArchiveExtractionLimits{
		MaxFileSize:  50 * 1024 * 1024,  // 50MB per file for updates
		MaxTotalSize: 500 * 1024 * 1024, // 500MB total for update package
		MaxFileCount: 1000,              // 1000 files max for update
		MaxDepth:     10,                // 10 levels deep max
	}
	tracker := security.NewArchiveExtractionTracker(limits)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading archive: %w", err)
		}

		// Skip non-regular files and directories for security
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir {
			u.logger.Warn("Skipping unsupported file type in archive: %s (type: %c)",
				header.Name, header.Typeflag)
			continue
		}

		// Comprehensive validation of archive entry
		if err := security.ValidateArchiveEntry(header.Name, header.Size, targetDir, tracker); err != nil {
			// Log security event
			event := security.NewSecurityEvent(
				security.InvalidArchiveEntry,
				security.SeverityHigh,
				"updater",
				"Malicious or invalid archive entry detected",
			).AddDetail("archive_path", header.Name).
				AddDetail("file_size", header.Size).
				AddDetail("target_dir", targetDir).
				AddDetail("error", err.Error()).
				SetRemediation("Ensure archive does not contain malicious entries or exceed limits")

			if eventJSON, jsonErr := event.ToJSON(); jsonErr == nil {
				u.logger.Warn("Security event: %s", string(eventJSON))
			}

			return fmt.Errorf("malicious archive entry detected: %w", err)
		}

		target := filepath.Join(targetDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			// Limit directory permissions for security - safe conversion with range check
			var mode os.FileMode
			if header.Mode >= 0 && header.Mode <= 0777 {
				mode = os.FileMode(header.Mode) & 0777
			} else {
				mode = 0750 // Default safe mode
			}
			if mode > 0750 {
				mode = 0750
			}
			if err := os.MkdirAll(target, mode); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", target, err)
			}

			// Record directory creation (size 0)
			tracker.RecordExtraction(0)

		case tar.TypeReg:
			// Ensure directory exists
			if err := os.MkdirAll(filepath.Dir(target), 0750); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", target, err)
			}

			// Limit file permissions for security - safe conversion with range check
			var mode os.FileMode
			if header.Mode >= 0 && header.Mode <= 0777 {
				mode = os.FileMode(header.Mode) & 0777
			} else {
				mode = 0640 // Default safe mode
			}
			if mode > 0640 {
				mode = 0640
			}

			// Create file
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", target, err)
			}

			// Copy content with size limit to prevent decompression bombs
			// Use the file size from header, but cap it at the tracker's limit
			maxSize := header.Size
			if maxSize > limits.MaxFileSize {
				maxSize = limits.MaxFileSize
			}

			limited := io.LimitReader(tr, maxSize)
			written, err := io.Copy(file, limited)
			if err != nil {
				if closeErr := file.Close(); closeErr != nil {
					u.logger.Error("Error closing file: %v", closeErr)
				}
				return fmt.Errorf("failed to write file %s: %w", target, err)
			}

			if err := file.Close(); err != nil {
				u.logger.Error("Error closing file: %v", err)
				return fmt.Errorf("failed to close file %s: %w", target, err)
			}

			// Verify that we extracted the expected amount
			if written != header.Size && header.Size <= limits.MaxFileSize {
				return fmt.Errorf("file size mismatch for %s: expected %d, got %d",
					target, header.Size, written)
			}

			// Record successful extraction
			tracker.RecordExtraction(written)

			u.logger.Debug("Extracted file: %s (%d bytes)", header.Name, written)
		}
	}

	// Log extraction statistics
	fileCount, totalSize := tracker.GetStats()
	u.logger.Info("Archive extraction completed: %d files, %d bytes total", fileCount, totalSize)

	return nil
}

// StartUpdateRoutine starts the automatic update checking routine
func (u *Updater) StartUpdateRoutine() {
	if !u.config.Update.Enabled {
		u.logger.Info("Automatic updates are disabled")
		return
	}

	interval := time.Duration(u.config.Update.CheckInterval) * time.Hour
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Initial check
	u.performUpdateCheck()

	for range ticker.C {
		u.performUpdateCheck()
	}
}

// performUpdateCheck performs an update check and applies if configured
func (u *Updater) performUpdateCheck() {
	info, err := u.CheckForUpdates()
	if err != nil {
		u.logger.Error("Update check failed: %v", err)
		return
	}

	if info == nil {
		return
	}

	// Check if auto-update is enabled or if it's a critical update
	if !u.config.Update.AutoUpdate && !info.Critical {
		u.logger.Info("Update available but auto-update is disabled: %s", info.Version)
		return
	}

	// Download update
	packagePath, err := u.DownloadUpdate(info)
	if err != nil {
		u.logger.Error("Failed to download update: %v", err)
		return
	}

	// Apply update
	if err := u.ApplyUpdate(packagePath); err != nil {
		u.logger.Error("Failed to apply update: %v", err)
		return
	}

	u.logger.Info("Update staged successfully, agent will restart to complete update")
}
