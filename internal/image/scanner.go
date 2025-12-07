package image

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	yarav1alpha1 "github.com/yara-operator/yara-operator/api/v1alpha1"
	"github.com/yara-operator/yara-operator/internal/yara"
)

// Scanner handles container image scanning
type Scanner struct {
	yaraScanner  *yara.Scanner
	httpClient   *http.Client
	secretRules  []SecretRule
	vulnPatterns []VulnPattern
}

// SecretRule defines a pattern for detecting secrets
type SecretRule struct {
	Name     string
	Type     string
	Pattern  *regexp.Regexp
	Severity string
}

// VulnPattern defines a pattern for detecting known vulnerabilities
type VulnPattern struct {
	ID          string
	Package     string
	Version     string
	Severity    string
	Description string
	Pattern     *regexp.Regexp
}

// ImageManifest represents a container image manifest
type ImageManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"layers"`
}

// ImageConfig represents image configuration
type ImageConfig struct {
	History []struct {
		CreatedBy  string `json:"created_by"`
		EmptyLayer bool   `json:"empty_layer,omitempty"`
	} `json:"history"`
}

// NewScanner creates a new image scanner
func NewScanner(yaraScanner *yara.Scanner) *Scanner {
	s := &Scanner{
		yaraScanner: yaraScanner,
		httpClient:  &http.Client{},
	}
	s.initSecretRules()
	s.initVulnPatterns()
	return s
}

// initSecretRules initializes patterns for detecting secrets
func (s *Scanner) initSecretRules() {
	s.secretRules = []SecretRule{
		{
			Name:     "AWS Access Key",
			Type:     "aws_access_key",
			Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Severity: "critical",
		},
		{
			Name:     "AWS Secret Key",
			Type:     "aws_secret_key",
			Pattern:  regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
			Severity: "critical",
		},
		{
			Name:     "GitHub Token",
			Type:     "github_token",
			Pattern:  regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
			Severity: "critical",
		},
		{
			Name:     "GitHub OAuth",
			Type:     "github_oauth",
			Pattern:  regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
			Severity: "critical",
		},
		{
			Name:     "Private Key",
			Type:     "private_key",
			Pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			Severity: "critical",
		},
		{
			Name:     "Generic API Key",
			Type:     "api_key",
			Pattern:  regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([a-zA-Z0-9]{32,64})['"]?`),
			Severity: "high",
		},
		{
			Name:     "Generic Secret",
			Type:     "generic_secret",
			Pattern:  regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?`),
			Severity: "high",
		},
		{
			Name:     "Database URL",
			Type:     "database_url",
			Pattern:  regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+`),
			Severity: "critical",
		},
		{
			Name:     "JWT Token",
			Type:     "jwt_token",
			Pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`),
			Severity: "high",
		},
		{
			Name:     "Slack Token",
			Type:     "slack_token",
			Pattern:  regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`),
			Severity: "high",
		},
		{
			Name:     "Google API Key",
			Type:     "google_api_key",
			Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
			Severity: "high",
		},
		{
			Name:     "Stripe Key",
			Type:     "stripe_key",
			Pattern:  regexp.MustCompile(`(?i)(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}`),
			Severity: "critical",
		},
	}
}

// initVulnPatterns initializes patterns for detecting known vulnerabilities
func (s *Scanner) initVulnPatterns() {
	s.vulnPatterns = []VulnPattern{
		{
			ID:          "CVE-2021-44228",
			Package:     "log4j",
			Severity:    "critical",
			Description: "Log4Shell - Remote code execution in Apache Log4j",
			Pattern:     regexp.MustCompile(`log4j-core-2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)(\.[0-9]+)?\.jar`),
		},
		{
			ID:          "CVE-2021-45046",
			Package:     "log4j",
			Severity:    "critical",
			Description: "Log4j additional RCE vulnerability",
			Pattern:     regexp.MustCompile(`log4j-core-2\.15\.0\.jar`),
		},
		{
			ID:          "CVE-2022-22965",
			Package:     "spring-framework",
			Severity:    "critical",
			Description: "Spring4Shell - RCE in Spring Framework",
			Pattern:     regexp.MustCompile(`spring-beans-[4-5]\.[0-2]\.[0-9]+\.jar`),
		},
		{
			ID:          "CVE-2021-42013",
			Package:     "apache-httpd",
			Severity:    "critical",
			Description: "Apache HTTP Server path traversal",
			Pattern:     regexp.MustCompile(`httpd[/-]2\.4\.(49|50)`),
		},
		{
			ID:          "CVE-2014-0160",
			Package:     "openssl",
			Severity:    "critical",
			Description: "Heartbleed - OpenSSL vulnerability",
			Pattern:     regexp.MustCompile(`libssl\.so\.1\.0\.[01]`),
		},
		{
			ID:          "CVE-2014-6271",
			Package:     "bash",
			Severity:    "critical",
			Description: "Shellshock - Bash vulnerability",
			Pattern:     regexp.MustCompile(`bash-[1-3]\.[0-2]|bash-4\.[0-2]`),
		},
		{
			ID:          "CRYPTO-MINER",
			Package:     "cryptocurrency-miner",
			Severity:    "critical",
			Description: "Potential cryptocurrency miner detected",
			Pattern:     regexp.MustCompile(`(xmrig|minerd|cgminer|bfgminer|cpuminer|stratum\+tcp)`),
		},
		{
			ID:          "WEBSHELL-001",
			Package:     "webshell",
			Severity:    "critical",
			Description: "Potential web shell detected",
			Pattern:     regexp.MustCompile(`(c99shell|r57shell|wso\.php|b374k|weevely)`),
		},
		{
			ID:          "BACKDOOR-001",
			Package:     "backdoor",
			Severity:    "critical",
			Description: "Potential backdoor detected",
			Pattern:     regexp.MustCompile(`(reverse.shell|bind.shell|nc\s+-e|bash\s+-i\s+>&)`),
		},
	}
}

// ScanImage scans a container image and returns results
func (s *Scanner) ScanImage(ctx context.Context, imageRef string, yaraRules []string) (*yarav1alpha1.ImageScanResult, error) {
	result := &yarav1alpha1.ImageScanResult{
		Image:  imageRef,
		Layers: []yarav1alpha1.LayerScanResult{},
	}

	// Parse image reference
	registry, repository, tag := parseImageRef(imageRef)

	// Get authentication token for public registries
	token, err := s.getAuthToken(registry, repository)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth token: %w", err)
	}

	// Fetch manifest
	manifest, err := s.fetchManifest(registry, repository, tag, token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}

	result.Digest = manifest.Config.Digest

	// Fetch image config for layer history
	config, err := s.fetchImageConfig(registry, repository, manifest.Config.Digest, token)
	if err != nil {
		// Non-fatal, continue without config
		config = &ImageConfig{}
	}

	// Calculate total size
	for _, layer := range manifest.Layers {
		result.Size += layer.Size
	}

	// Scan each layer
	historyIdx := 0
	for i, layer := range manifest.Layers {
		layerResult := yarav1alpha1.LayerScanResult{
			Digest: layer.Digest,
			Size:   layer.Size,
		}

		// Get the command that created this layer
		for historyIdx < len(config.History) {
			if !config.History[historyIdx].EmptyLayer {
				layerResult.Command = config.History[historyIdx].CreatedBy
				historyIdx++
				break
			}
			historyIdx++
		}

		// Scan layer content
		matches, vulns, secrets, err := s.scanLayer(ctx, registry, repository, layer.Digest, token, yaraRules)
		if err != nil {
			// Log error but continue with other layers
			continue
		}

		layerResult.Matches = matches
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
		result.SecretsFound = append(result.SecretsFound, secrets...)

		if len(matches) > 0 {
			result.MalwareDetected = true
		}

		result.Layers = append(result.Layers, layerResult)

		// Check context cancellation
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		_ = i // Suppress unused variable warning
	}

	return result, nil
}

// parseImageRef parses an image reference into registry, repository, and tag
func parseImageRef(ref string) (registry, repository, tag string) {
	// Default values
	registry = "registry-1.docker.io"
	tag = "latest"

	// Remove any digest
	if idx := strings.Index(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}

	// Extract tag
	if idx := strings.LastIndex(ref, ":"); idx != -1 && !strings.Contains(ref[idx:], "/") {
		tag = ref[idx+1:]
		ref = ref[:idx]
	}

	// Extract registry and repository
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) == 1 {
		// Just image name, use library namespace
		repository = "library/" + parts[0]
	} else if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") {
		// First part is a registry
		registry = parts[0]
		repository = parts[1]
	} else {
		// First part is namespace
		repository = ref
	}

	// Handle Docker Hub special case
	if registry == "docker.io" {
		registry = "registry-1.docker.io"
	}

	return
}

// getAuthToken gets an authentication token for the registry
func (s *Scanner) getAuthToken(registry, repository string) (string, error) {
	// Docker Hub authentication
	if registry == "registry-1.docker.io" {
		url := fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", repository)
		resp, err := s.httpClient.Get(url)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		var result struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", err
		}
		return result.Token, nil
	}

	// GitHub Container Registry
	if registry == "ghcr.io" {
		url := fmt.Sprintf("https://ghcr.io/token?scope=repository:%s:pull", repository)
		resp, err := s.httpClient.Get(url)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		var result struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return "", err
		}
		return result.Token, nil
	}

	// Quay.io - public images don't require auth
	if registry == "quay.io" {
		return "", nil
	}

	return "", nil
}

// fetchManifest fetches the image manifest
func (s *Scanner) fetchManifest(registry, repository, tag, token string) (*ImageManifest, error) {
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", registry, repository, tag)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch manifest: %s - %s", resp.Status, string(body))
	}

	var manifest ImageManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

// fetchImageConfig fetches the image configuration
func (s *Scanner) fetchImageConfig(registry, repository, digest, token string) (*ImageConfig, error) {
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, digest)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch config: %s", resp.Status)
	}

	var config ImageConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// scanLayer scans a single layer and returns matches, vulnerabilities, and secrets
func (s *Scanner) scanLayer(ctx context.Context, registry, repository, digest, token string, yaraRules []string) (
	[]yarav1alpha1.ScanMatch,
	[]yarav1alpha1.Vulnerability,
	[]yarav1alpha1.SecretFinding,
	error,
) {
	var matches []yarav1alpha1.ScanMatch
	var vulns []yarav1alpha1.Vulnerability
	var secrets []yarav1alpha1.SecretFinding

	// Fetch layer blob
	url := fmt.Sprintf("https://%s/v2/%s/blobs/%s", registry, repository, digest)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("failed to fetch layer: %s", resp.Status)
	}

	// Layer is a gzipped tar archive
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, nil, nil, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	// Scan each file in the layer
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// Skip directories and large files
		if header.Typeflag == tar.TypeDir || header.Size > 50*1024*1024 {
			continue
		}

		// Read file content
		content := make([]byte, header.Size)
		if _, err := io.ReadFull(tarReader, content); err != nil {
			continue
		}

		// Check for vulnerabilities by filename
		for _, vuln := range s.vulnPatterns {
			if vuln.Pattern.MatchString(header.Name) {
				vulns = append(vulns, yarav1alpha1.Vulnerability{
					ID:          vuln.ID,
					Severity:    vuln.Severity,
					Package:     vuln.Package,
					Description: vuln.Description,
					DetectedBy:  "filename_pattern",
				})
			}
		}

		// Check for secrets in text files
		if isTextFile(header.Name) && len(content) < 1024*1024 {
			contentStr := string(content)

			// Check vulnerability patterns in content
			for _, vuln := range s.vulnPatterns {
				if vuln.Pattern.MatchString(contentStr) {
					vulns = append(vulns, yarav1alpha1.Vulnerability{
						ID:          vuln.ID,
						Severity:    vuln.Severity,
						Package:     vuln.Package,
						Description: vuln.Description,
						DetectedBy:  "content_pattern",
					})
				}
			}

			// Check for secrets
			for _, rule := range s.secretRules {
				if matches := rule.Pattern.FindStringSubmatch(contentStr); len(matches) > 0 {
					partial := matches[0]
					if len(partial) > 20 {
						partial = partial[:10] + "..." + partial[len(partial)-5:]
					}
					secrets = append(secrets, yarav1alpha1.SecretFinding{
						Type:     rule.Type,
						Path:     header.Name,
						Partial:  partial,
						Severity: rule.Severity,
					})
				}
			}
		}

		// Run YARA rules on file content
		if len(yaraRules) > 0 {
			yaraMatches, err := s.yaraScanner.ScanData(content, yaraRules)
			if err == nil && len(yaraMatches) > 0 {
				for i := range yaraMatches {
					yaraMatches[i].Namespace = header.Name
				}
				matches = append(matches, yaraMatches...)
			}
		}
	}

	return matches, vulns, secrets, nil
}

// isTextFile checks if a file is likely a text file based on extension
func isTextFile(name string) bool {
	textExtensions := []string{
		".txt", ".md", ".json", ".yaml", ".yml", ".xml", ".html", ".htm",
		".js", ".ts", ".py", ".rb", ".go", ".java", ".c", ".cpp", ".h",
		".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
		".conf", ".cfg", ".ini", ".env", ".properties",
		".sql", ".dockerfile", ".tf", ".tfvars",
	}

	nameLower := strings.ToLower(name)
	for _, ext := range textExtensions {
		if strings.HasSuffix(nameLower, ext) {
			return true
		}
	}

	// Also check common filenames
	baseName := strings.ToLower(name[strings.LastIndex(name, "/")+1:])
	textFiles := []string{
		"dockerfile", "makefile", "gemfile", "rakefile", "procfile",
		".env", ".gitignore", ".dockerignore", ".npmrc", ".yarnrc",
		"package.json", "composer.json", "requirements.txt", "go.mod", "go.sum",
	}
	for _, f := range textFiles {
		if baseName == f {
			return true
		}
	}

	return false
}

// CalculateRiskScore calculates an overall risk score from scan results
func CalculateRiskScore(result *yarav1alpha1.ImageScanResult) int {
	score := 0

	// Vulnerability scoring
	for _, v := range result.Vulnerabilities {
		switch v.Severity {
		case "critical":
			score += 25
		case "high":
			score += 15
		case "medium":
			score += 5
		case "low":
			score += 1
		}
	}

	// Secret scoring
	for _, s := range result.SecretsFound {
		switch s.Severity {
		case "critical":
			score += 20
		case "high":
			score += 10
		case "medium":
			score += 3
		}
	}

	// Malware detection is severe
	if result.MalwareDetected {
		score += 50
	}

	// YARA matches
	for _, layer := range result.Layers {
		score += len(layer.Matches) * 10
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// CalculateSummary generates a summary from scan results
func CalculateSummary(result *yarav1alpha1.ImageScanResult) *yarav1alpha1.ScanSummary {
	summary := &yarav1alpha1.ScanSummary{}

	for _, v := range result.Vulnerabilities {
		switch v.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
	}

	for _, s := range result.SecretsFound {
		switch s.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		}
	}

	summary.RiskScore = CalculateRiskScore(result)

	return summary
}

// HashString creates a SHA256 hash of a string
func HashString(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
