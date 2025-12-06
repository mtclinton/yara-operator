// Package v1alpha1 contains API Schema definitions for the yara v1alpha1 API group
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=yr
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// YaraRule is the Schema for the yararules API
type YaraRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   YaraRuleSpec   `json:"spec,omitempty"`
	Status YaraRuleStatus `json:"status,omitempty"`
}

// YaraRuleSpec defines the desired state of YaraRule
type YaraRuleSpec struct {
	// Name is the name of the YARA rule
	Name string `json:"name"`

	// Content is the raw YARA rule content
	Content string `json:"content"`

	// Description provides additional context about the rule
	// +optional
	Description string `json:"description,omitempty"`

	// Tags are labels for categorizing rules
	// +optional
	Tags []string `json:"tags,omitempty"`

	// Enabled determines if the rule should be used in scans
	// +optional
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`
}

// YaraRuleStatus defines the observed state of YaraRule
type YaraRuleStatus struct {
	// Phase represents the current phase of the rule
	// +kubebuilder:validation:Enum=Pending;Valid;Invalid
	Phase string `json:"phase,omitempty"`

	// Message provides additional information about the status
	Message string `json:"message,omitempty"`

	// LastValidated is the timestamp of the last validation
	LastValidated *metav1.Time `json:"lastValidated,omitempty"`
}

// +kubebuilder:object:root=true

// YaraRuleList contains a list of YaraRule
type YaraRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []YaraRule `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ys
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Matches",type=integer,JSONPath=`.status.matchCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// YaraScan is the Schema for the yarascans API
type YaraScan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   YaraScanSpec   `json:"spec,omitempty"`
	Status YaraScanStatus `json:"status,omitempty"`
}

// YaraScanSpec defines the desired state of YaraScan
type YaraScanSpec struct {
	// Target specifies what to scan
	Target ScanTarget `json:"target"`

	// RuleSelector selects which YaraRules to use
	// +optional
	RuleSelector *metav1.LabelSelector `json:"ruleSelector,omitempty"`

	// RuleNames explicitly specifies rule names to use
	// +optional
	RuleNames []string `json:"ruleNames,omitempty"`

	// InlineRules allows specifying rules directly in the scan
	// +optional
	InlineRules []InlineRule `json:"inlineRules,omitempty"`

	// Timeout is the maximum duration for the scan in seconds
	// +optional
	// +kubebuilder:default=300
	Timeout int `json:"timeout,omitempty"`

	// RetainResults specifies how long to retain results (in hours)
	// +optional
	// +kubebuilder:default=24
	RetainResults int `json:"retainResults,omitempty"`
}

// ScanTarget defines what should be scanned
type ScanTarget struct {
	// Type is the type of target (file, url, container, configmap)
	// +kubebuilder:validation:Enum=file;url;data;configmap;secret;image
	Type string `json:"type"`

	// Value is the target value (path, URL, base64 data, resource name, image reference)
	Value string `json:"value"`

	// Namespace for configmap/secret targets
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Key for configmap/secret targets
	// +optional
	Key string `json:"key,omitempty"`

	// Registry credentials secret name for private images
	// +optional
	ImagePullSecret string `json:"imagePullSecret,omitempty"`

	// ScanLayers determines whether to scan individual image layers
	// +optional
	// +kubebuilder:default=true
	ScanLayers bool `json:"scanLayers,omitempty"`
}

// ImageScanResult contains detailed results from image scanning
type ImageScanResult struct {
	// Image is the full image reference
	Image string `json:"image"`

	// Digest is the image digest
	Digest string `json:"digest,omitempty"`

	// Layers contains scan results per layer
	Layers []LayerScanResult `json:"layers,omitempty"`

	// Vulnerabilities found in the image
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`

	// Secrets detected in the image
	SecretsFound []SecretFinding `json:"secretsFound,omitempty"`

	// MalwareDetected indicates if malware patterns were found
	MalwareDetected bool `json:"malwareDetected"`

	// Size is the total image size
	Size int64 `json:"size,omitempty"`
}

// LayerScanResult contains scan results for a single image layer
type LayerScanResult struct {
	// Digest is the layer digest
	Digest string `json:"digest"`

	// Size is the layer size
	Size int64 `json:"size"`

	// Matches found in this layer
	Matches []ScanMatch `json:"matches,omitempty"`

	// Command is the Dockerfile command that created this layer
	Command string `json:"command,omitempty"`
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	// ID is the vulnerability identifier (CVE, etc.)
	ID string `json:"id"`

	// Severity level (critical, high, medium, low)
	Severity string `json:"severity"`

	// Package is the affected package name
	Package string `json:"package,omitempty"`

	// Version is the affected version
	Version string `json:"version,omitempty"`

	// Description of the vulnerability
	Description string `json:"description,omitempty"`

	// FixedIn is the version that fixes this vulnerability
	FixedIn string `json:"fixedIn,omitempty"`

	// DetectedBy is the rule that detected this
	DetectedBy string `json:"detectedBy,omitempty"`
}

// SecretFinding represents a detected secret or credential
type SecretFinding struct {
	// Type of secret (api_key, password, private_key, etc.)
	Type string `json:"type"`

	// Path where the secret was found
	Path string `json:"path"`

	// Line number if applicable
	Line int `json:"line,omitempty"`

	// Partial shows a redacted portion of the finding
	Partial string `json:"partial,omitempty"`

	// Severity level
	Severity string `json:"severity"`
}

// InlineRule defines a YARA rule inline
type InlineRule struct {
	// Name of the inline rule
	Name string `json:"name"`

	// Content of the YARA rule
	Content string `json:"content"`
}

// YaraScanStatus defines the observed state of YaraScan
type YaraScanStatus struct {
	// Phase represents the current phase of the scan
	// +kubebuilder:validation:Enum=Pending;Running;Completed;Failed
	Phase string `json:"phase,omitempty"`

	// StartTime is when the scan started
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the scan completed
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// MatchCount is the number of rule matches found
	MatchCount int `json:"matchCount,omitempty"`

	// Matches contains the detailed match information
	Matches []ScanMatch `json:"matches,omitempty"`

	// Message provides additional information about the status
	Message string `json:"message,omitempty"`

	// ScannedBytes is the size of scanned data
	ScannedBytes int64 `json:"scannedBytes,omitempty"`

	// ImageResult contains detailed image scan results (for image targets)
	ImageResult *ImageScanResult `json:"imageResult,omitempty"`

	// VulnerabilityCount is the number of vulnerabilities found
	VulnerabilityCount int `json:"vulnerabilityCount,omitempty"`

	// SecretsCount is the number of secrets/credentials found
	SecretsCount int `json:"secretsCount,omitempty"`

	// Summary provides a quick overview
	Summary *ScanSummary `json:"summary,omitempty"`
}

// ScanSummary provides a quick overview of scan results
type ScanSummary struct {
	// Critical severity findings
	Critical int `json:"critical"`
	// High severity findings
	High int `json:"high"`
	// Medium severity findings
	Medium int `json:"medium"`
	// Low severity findings
	Low int `json:"low"`
	// RiskScore is an overall risk score (0-100)
	RiskScore int `json:"riskScore"`
}

// ScanMatch represents a YARA rule match
type ScanMatch struct {
	// Rule is the name of the matched rule
	Rule string `json:"rule"`

	// Namespace is the YARA namespace of the rule
	Namespace string `json:"namespace,omitempty"`

	// Tags are the tags associated with the matched rule
	Tags []string `json:"tags,omitempty"`

	// Strings contains the matched strings
	Strings []MatchString `json:"strings,omitempty"`

	// Meta contains rule metadata
	Meta map[string]string `json:"meta,omitempty"`
}

// MatchString represents a matched string within a rule
type MatchString struct {
	// Name is the identifier of the string
	Name string `json:"name"`

	// Offset is the position in the data where the match was found
	Offset int64 `json:"offset"`

	// Length is the length of the matched data
	Length int `json:"length"`

	// Data is a hex representation of matched bytes (truncated for large matches)
	Data string `json:"data,omitempty"`
}

// +kubebuilder:object:root=true

// YaraScanList contains a list of YaraScan
type YaraScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []YaraScan `json:"items"`
}

// Phase constants
const (
	PhasePending   = "Pending"
	PhaseRunning   = "Running"
	PhaseCompleted = "Completed"
	PhaseFailed    = "Failed"
	PhaseValid     = "Valid"
	PhaseInvalid   = "Invalid"
)

