package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	yarav1alpha1 "github.com/yara-operator/yara-operator/api/v1alpha1"
)

var (
	scheme    = runtime.NewScheme()
	k8sClient client.Client
	namespace string
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(yarav1alpha1.AddToScheme(scheme))
}

// API Request/Response types
type ScanRequest struct {
	// Data to scan (base64 encoded)
	Data string `json:"data,omitempty"`
	// URL to fetch and scan
	URL string `json:"url,omitempty"`
	// Raw text to scan
	Text string `json:"text,omitempty"`
	// Container image to scan (e.g., "nginx:latest", "ghcr.io/org/image:tag")
	Image string `json:"image,omitempty"`
	// Inline YARA rules to use
	Rules []string `json:"rules,omitempty"`
	// Named rules to use (from YaraRule resources)
	RuleNames []string `json:"ruleNames,omitempty"`
	// Whether to scan all image layers (default: true)
	ScanLayers *bool `json:"scanLayers,omitempty"`
}

type ScanResponse struct {
	ID                 string                        `json:"id"`
	Status             string                        `json:"status"`
	StartTime          *time.Time                    `json:"startTime,omitempty"`
	EndTime            *time.Time                    `json:"endTime,omitempty"`
	MatchCount         int                           `json:"matchCount"`
	Matches            []yarav1alpha1.ScanMatch      `json:"matches,omitempty"`
	Message            string                        `json:"message,omitempty"`
	ScannedBytes       int64                         `json:"scannedBytes,omitempty"`
	// Image scan specific fields
	ImageResult        *yarav1alpha1.ImageScanResult `json:"imageResult,omitempty"`
	VulnerabilityCount int                           `json:"vulnerabilityCount,omitempty"`
	SecretsCount       int                           `json:"secretsCount,omitempty"`
	Summary            *yarav1alpha1.ScanSummary     `json:"summary,omitempty"`
	TargetType         string                        `json:"targetType,omitempty"`
}

type RuleResponse struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Enabled     bool     `json:"enabled"`
	Status      string   `json:"status"`
	Content     string   `json:"content,omitempty"`
}

type CreateRuleRequest struct {
	Name        string   `json:"name"`
	Content     string   `json:"content"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func main() {
	var addr string
	flag.StringVar(&addr, "addr", ":8090", "API server address")
	flag.StringVar(&namespace, "namespace", "default", "Kubernetes namespace for resources")
	flag.Parse()

	// Get namespace from environment if set
	if ns := os.Getenv("NAMESPACE"); ns != "" {
		namespace = ns
	}

	// Initialize Kubernetes client
	cfg, err := config.GetConfig()
	if err != nil {
		log.Fatalf("Failed to get Kubernetes config: %v", err)
	}

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Setup router
	r := mux.NewRouter()
	api := r.PathPrefix("/api/v1").Subrouter()

	// Scan endpoints
	api.HandleFunc("/scans", createScan).Methods("POST")
	api.HandleFunc("/scans", listScans).Methods("GET")
	api.HandleFunc("/scans/{id}", getScan).Methods("GET")
	api.HandleFunc("/scans/{id}", deleteScan).Methods("DELETE")

	// Rule endpoints
	api.HandleFunc("/rules", listRules).Methods("GET")
	api.HandleFunc("/rules", createRule).Methods("POST")
	api.HandleFunc("/rules/{name}", getRule).Methods("GET")
	api.HandleFunc("/rules/{name}", deleteRule).Methods("DELETE")

	// Health endpoint
	r.HandleFunc("/health", healthCheck).Methods("GET")
	r.HandleFunc("/ready", readyCheck).Methods("GET")

	// CORS configuration for GitHub Pages
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
		MaxAge:           86400,
	})

	handler := c.Handler(r)

	log.Printf("YARA API Server starting on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// Scan handlers

func createScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Determine target type and value
	var targetType, targetValue string
	var scanLayers bool = true
	switch {
	case req.Image != "":
		targetType = "image"
		targetValue = req.Image
		if req.ScanLayers != nil {
			scanLayers = *req.ScanLayers
		}
	case req.Data != "":
		targetType = "data"
		targetValue = req.Data
	case req.URL != "":
		targetType = "url"
		targetValue = req.URL
	case req.Text != "":
		targetType = "data"
		targetValue = base64.StdEncoding.EncodeToString([]byte(req.Text))
	default:
		respondError(w, http.StatusBadRequest, "Missing data", "Provide 'image', 'data', 'url', or 'text'")
		return
	}

	// Create inline rules
	var inlineRules []yarav1alpha1.InlineRule
	for i, rule := range req.Rules {
		inlineRules = append(inlineRules, yarav1alpha1.InlineRule{
			Name:    fmt.Sprintf("inline_%d", i),
			Content: rule,
		})
	}

	// Create YaraScan resource
	scan := &yarav1alpha1.YaraScan{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "api-scan-",
			Namespace:    namespace,
		},
		Spec: yarav1alpha1.YaraScanSpec{
			Target: yarav1alpha1.ScanTarget{
				Type:       targetType,
				Value:      targetValue,
				ScanLayers: scanLayers,
			},
			InlineRules: inlineRules,
			RuleNames:   req.RuleNames,
			Timeout:     600, // Longer timeout for image scans
		},
	}

	ctx := context.Background()
	if err := k8sClient.Create(ctx, scan); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create scan", err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, ScanResponse{
		ID:      scan.Name,
		Status:  string(yarav1alpha1.PhasePending),
		Message: "Scan created successfully",
	})
}

func listScans(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var scanList yarav1alpha1.YaraScanList
	if err := k8sClient.List(ctx, &scanList, client.InNamespace(namespace)); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to list scans", err.Error())
		return
	}

	var responses []ScanResponse
	for _, scan := range scanList.Items {
		resp := scanToResponse(&scan)
		responses = append(responses, resp)
	}

	respondJSON(w, http.StatusOK, responses)
}

func getScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := context.Background()
	var scan yarav1alpha1.YaraScan
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: id, Namespace: namespace}, &scan); err != nil {
		respondError(w, http.StatusNotFound, "Scan not found", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, scanToResponse(&scan))
}

func deleteScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	ctx := context.Background()
	scan := &yarav1alpha1.YaraScan{
		ObjectMeta: metav1.ObjectMeta{
			Name:      id,
			Namespace: namespace,
		},
	}
	if err := k8sClient.Delete(ctx, scan); err != nil {
		respondError(w, http.StatusNotFound, "Scan not found", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Rule handlers

func listRules(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	var ruleList yarav1alpha1.YaraRuleList
	if err := k8sClient.List(ctx, &ruleList, client.InNamespace(namespace)); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to list rules", err.Error())
		return
	}

	var responses []RuleResponse
	for _, rule := range ruleList.Items {
		responses = append(responses, RuleResponse{
			Name:        rule.Spec.Name,
			Description: rule.Spec.Description,
			Tags:        rule.Spec.Tags,
			Enabled:     rule.Spec.Enabled,
			Status:      rule.Status.Phase,
		})
	}

	respondJSON(w, http.StatusOK, responses)
}

func createRule(w http.ResponseWriter, r *http.Request) {
	var req CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Name == "" || req.Content == "" {
		respondError(w, http.StatusBadRequest, "Missing required fields", "Name and content are required")
		return
	}

	rule := &yarav1alpha1.YaraRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: namespace,
		},
		Spec: yarav1alpha1.YaraRuleSpec{
			Name:        req.Name,
			Content:     req.Content,
			Description: req.Description,
			Tags:        req.Tags,
			Enabled:     true,
		},
	}

	ctx := context.Background()
	if err := k8sClient.Create(ctx, rule); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create rule", err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, RuleResponse{
		Name:        rule.Spec.Name,
		Description: rule.Spec.Description,
		Tags:        rule.Spec.Tags,
		Enabled:     rule.Spec.Enabled,
		Status:      "Pending",
	})
}

func getRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	ctx := context.Background()
	var rule yarav1alpha1.YaraRule
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &rule); err != nil {
		respondError(w, http.StatusNotFound, "Rule not found", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, RuleResponse{
		Name:        rule.Spec.Name,
		Description: rule.Spec.Description,
		Tags:        rule.Spec.Tags,
		Enabled:     rule.Spec.Enabled,
		Status:      rule.Status.Phase,
		Content:     rule.Spec.Content,
	})
}

func deleteRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	ctx := context.Background()
	rule := &yarav1alpha1.YaraRule{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	if err := k8sClient.Delete(ctx, rule); err != nil {
		respondError(w, http.StatusNotFound, "Rule not found", err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Health handlers

func healthCheck(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func readyCheck(w http.ResponseWriter, r *http.Request) {
	// Check if we can list scans
	ctx := context.Background()
	var scanList yarav1alpha1.YaraScanList
	if err := k8sClient.List(ctx, &scanList, client.InNamespace(namespace), client.Limit(1)); err != nil {
		respondError(w, http.StatusServiceUnavailable, "Not ready", err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// Helper functions

func scanToResponse(scan *yarav1alpha1.YaraScan) ScanResponse {
	resp := ScanResponse{
		ID:                 scan.Name,
		Status:             scan.Status.Phase,
		MatchCount:         scan.Status.MatchCount,
		Matches:            scan.Status.Matches,
		Message:            scan.Status.Message,
		ScannedBytes:       scan.Status.ScannedBytes,
		ImageResult:        scan.Status.ImageResult,
		VulnerabilityCount: scan.Status.VulnerabilityCount,
		SecretsCount:       scan.Status.SecretsCount,
		Summary:            scan.Status.Summary,
		TargetType:         scan.Spec.Target.Type,
	}

	if scan.Status.StartTime != nil {
		t := scan.Status.StartTime.Time
		resp.StartTime = &t
	}
	if scan.Status.CompletionTime != nil {
		t := scan.Status.CompletionTime.Time
		resp.EndTime = &t
	}

	return resp
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, error, message string) {
	respondJSON(w, status, ErrorResponse{
		Error:   error,
		Message: message,
	})
}

