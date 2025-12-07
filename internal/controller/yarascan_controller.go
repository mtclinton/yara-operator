package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	yarav1alpha1 "github.com/yara-operator/yara-operator/api/v1alpha1"
	"github.com/yara-operator/yara-operator/internal/image"
	"github.com/yara-operator/yara-operator/internal/yara"
)

// YaraScanReconciler reconciles a YaraScan object
type YaraScanReconciler struct {
	client.Client
	Log          logr.Logger
	Scheme       *runtime.Scheme
	YaraScanner  *yara.Scanner
	ImageScanner *image.Scanner
}

// +kubebuilder:rbac:groups=yara.security.io,resources=yarascans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=yara.security.io,resources=yarascans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=yara.security.io,resources=yarascans/finalizers,verbs=update
// +kubebuilder:rbac:groups=yara.security.io,resources=yararules,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile handles YaraScan reconciliation
func (r *YaraScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("yarascan", req.NamespacedName)

	// Fetch the YaraScan instance
	var scan yarav1alpha1.YaraScan
	if err := r.Get(ctx, req.NamespacedName, &scan); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Skip if already completed or failed
	if scan.Status.Phase == yarav1alpha1.PhaseCompleted || scan.Status.Phase == yarav1alpha1.PhaseFailed {
		return ctrl.Result{}, nil
	}

	log.Info("Reconciling YaraScan", "target", scan.Spec.Target.Value)

	// Update status to Running
	if scan.Status.Phase != yarav1alpha1.PhaseRunning {
		scan.Status.Phase = yarav1alpha1.PhaseRunning
		now := metav1.Now()
		scan.Status.StartTime = &now
		if err := r.Status().Update(ctx, &scan); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Collect rules to use
	rules, err := r.collectRules(ctx, &scan)
	if err != nil {
		return r.failScan(ctx, &scan, fmt.Sprintf("Failed to collect rules: %v", err))
	}

	if len(rules) == 0 {
		return r.failScan(ctx, &scan, "No rules available for scanning")
	}

	// Handle image scanning differently
	if scan.Spec.Target.Type == "image" {
		return r.handleImageScan(ctx, &scan, rules)
	}

	// Get data to scan
	data, err := r.getTargetData(ctx, &scan)
	if err != nil {
		return r.failScan(ctx, &scan, fmt.Sprintf("Failed to get target data: %v", err))
	}

	// Perform the scan
	matches, err := r.YaraScanner.ScanData(data, rules)
	if err != nil {
		return r.failScan(ctx, &scan, fmt.Sprintf("Scan failed: %v", err))
	}

	// Update status with results
	scan.Status.Phase = yarav1alpha1.PhaseCompleted
	now := metav1.Now()
	scan.Status.CompletionTime = &now
	scan.Status.MatchCount = len(matches)
	scan.Status.Matches = matches
	scan.Status.ScannedBytes = int64(len(data))
	scan.Status.Message = fmt.Sprintf("Scan completed successfully. Found %d matches.", len(matches))

	if err := r.Status().Update(ctx, &scan); err != nil {
		log.Error(err, "Failed to update YaraScan status")
		return ctrl.Result{}, err
	}

	log.Info("Scan completed", "matches", len(matches))
	return ctrl.Result{}, nil
}

// collectRules gathers all applicable YARA rules for the scan
func (r *YaraScanReconciler) collectRules(ctx context.Context, scan *yarav1alpha1.YaraScan) ([]string, error) {
	var rules []string

	// Add inline rules
	for _, inlineRule := range scan.Spec.InlineRules {
		rules = append(rules, inlineRule.Content)
	}

	// Get rules by name
	if len(scan.Spec.RuleNames) > 0 {
		var ruleList yarav1alpha1.YaraRuleList
		if err := r.List(ctx, &ruleList, client.InNamespace(scan.Namespace)); err != nil {
			return nil, err
		}

		for _, rule := range ruleList.Items {
			for _, name := range scan.Spec.RuleNames {
				if rule.Spec.Name == name && rule.Spec.Enabled && rule.Status.Phase == yarav1alpha1.PhaseValid {
					rules = append(rules, rule.Spec.Content)
					break
				}
			}
		}
	}

	// Get rules by selector
	if scan.Spec.RuleSelector != nil {
		selector, err := labels.Parse(scan.Spec.RuleSelector.String())
		if err != nil {
			return nil, fmt.Errorf("invalid rule selector: %w", err)
		}

		var ruleList yarav1alpha1.YaraRuleList
		if err := r.List(ctx, &ruleList, client.InNamespace(scan.Namespace), client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return nil, err
		}

		for _, rule := range ruleList.Items {
			if rule.Spec.Enabled && rule.Status.Phase == yarav1alpha1.PhaseValid {
				rules = append(rules, rule.Spec.Content)
			}
		}
	}

	// If no specific rules were requested, use all enabled valid rules
	if len(scan.Spec.RuleNames) == 0 && scan.Spec.RuleSelector == nil && len(scan.Spec.InlineRules) == 0 {
		var ruleList yarav1alpha1.YaraRuleList
		if err := r.List(ctx, &ruleList, client.InNamespace(scan.Namespace)); err != nil {
			return nil, err
		}

		for _, rule := range ruleList.Items {
			if rule.Spec.Enabled && rule.Status.Phase == yarav1alpha1.PhaseValid {
				rules = append(rules, rule.Spec.Content)
			}
		}
	}

	return rules, nil
}

// getTargetData retrieves the data to be scanned based on target type
func (r *YaraScanReconciler) getTargetData(ctx context.Context, scan *yarav1alpha1.YaraScan) ([]byte, error) {
	switch scan.Spec.Target.Type {
	case "data":
		// Base64 encoded data
		return base64.StdEncoding.DecodeString(scan.Spec.Target.Value)

	case "url":
		// Fetch from URL
		resp, err := http.Get(scan.Spec.Target.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch URL: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("URL returned status %d", resp.StatusCode)
		}

		return io.ReadAll(resp.Body)

	case "configmap":
		// Get from ConfigMap
		ns := scan.Spec.Target.Namespace
		if ns == "" {
			ns = scan.Namespace
		}

		var cm corev1.ConfigMap
		if err := r.Get(ctx, types.NamespacedName{Name: scan.Spec.Target.Value, Namespace: ns}, &cm); err != nil {
			return nil, fmt.Errorf("failed to get ConfigMap: %w", err)
		}

		if scan.Spec.Target.Key != "" {
			if data, ok := cm.Data[scan.Spec.Target.Key]; ok {
				return []byte(data), nil
			}
			if data, ok := cm.BinaryData[scan.Spec.Target.Key]; ok {
				return data, nil
			}
			return nil, fmt.Errorf("key %s not found in ConfigMap", scan.Spec.Target.Key)
		}

		// Concatenate all data
		var allData strings.Builder
		for _, v := range cm.Data {
			allData.WriteString(v)
		}
		return []byte(allData.String()), nil

	case "secret":
		// Get from Secret
		ns := scan.Spec.Target.Namespace
		if ns == "" {
			ns = scan.Namespace
		}

		var secret corev1.Secret
		if err := r.Get(ctx, types.NamespacedName{Name: scan.Spec.Target.Value, Namespace: ns}, &secret); err != nil {
			return nil, fmt.Errorf("failed to get Secret: %w", err)
		}

		if scan.Spec.Target.Key != "" {
			if data, ok := secret.Data[scan.Spec.Target.Key]; ok {
				return data, nil
			}
			return nil, fmt.Errorf("key %s not found in Secret", scan.Spec.Target.Key)
		}

		// Concatenate all data
		var allData []byte
		for _, v := range secret.Data {
			allData = append(allData, v...)
		}
		return allData, nil

	default:
		return nil, fmt.Errorf("unsupported target type: %s", scan.Spec.Target.Type)
	}
}

// failScan updates the scan status to failed
func (r *YaraScanReconciler) failScan(ctx context.Context, scan *yarav1alpha1.YaraScan, message string) (ctrl.Result, error) {
	scan.Status.Phase = yarav1alpha1.PhaseFailed
	now := metav1.Now()
	scan.Status.CompletionTime = &now
	scan.Status.Message = message

	if err := r.Status().Update(ctx, scan); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// handleImageScan handles container image scanning
func (r *YaraScanReconciler) handleImageScan(ctx context.Context, scan *yarav1alpha1.YaraScan, rules []string) (ctrl.Result, error) {
	log := r.Log.WithValues("yarascan", scan.Name, "image", scan.Spec.Target.Value)
	log.Info("Starting image scan")

	// Initialize image scanner if not already done
	if r.ImageScanner == nil {
		r.ImageScanner = image.NewScanner(r.YaraScanner)
	}

	// Perform the image scan
	imageResult, err := r.ImageScanner.ScanImage(ctx, scan.Spec.Target.Value, rules)
	if err != nil {
		return r.failScan(ctx, scan, fmt.Sprintf("Image scan failed: %v", err))
	}

	// Calculate summary
	summary := image.CalculateSummary(imageResult)

	// Count total matches across all layers
	matchCount := 0
	var allMatches []yarav1alpha1.ScanMatch
	for _, layer := range imageResult.Layers {
		matchCount += len(layer.Matches)
		allMatches = append(allMatches, layer.Matches...)
	}

	// Update status with results
	scan.Status.Phase = yarav1alpha1.PhaseCompleted
	now := metav1.Now()
	scan.Status.CompletionTime = &now
	scan.Status.MatchCount = matchCount
	scan.Status.Matches = allMatches
	scan.Status.ScannedBytes = imageResult.Size
	scan.Status.ImageResult = imageResult
	scan.Status.VulnerabilityCount = len(imageResult.Vulnerabilities)
	scan.Status.SecretsCount = len(imageResult.SecretsFound)
	scan.Status.Summary = summary

	// Generate message
	if imageResult.MalwareDetected {
		scan.Status.Message = fmt.Sprintf("MALWARE DETECTED. Risk Score: %d/100. Found %d vulnerabilities, %d secrets, %d YARA matches.",
			summary.RiskScore, len(imageResult.Vulnerabilities), len(imageResult.SecretsFound), matchCount)
	} else if summary.Critical > 0 {
		scan.Status.Message = fmt.Sprintf("Critical issues found. Risk Score: %d/100. Found %d critical, %d high, %d medium, %d low severity issues.",
			summary.RiskScore, summary.Critical, summary.High, summary.Medium, summary.Low)
	} else if summary.High > 0 {
		scan.Status.Message = fmt.Sprintf("High severity issues found. Risk Score: %d/100. Found %d high, %d medium, %d low severity issues.",
			summary.RiskScore, summary.High, summary.Medium, summary.Low)
	} else if summary.Medium > 0 || summary.Low > 0 {
		scan.Status.Message = fmt.Sprintf("Issues found. Risk Score: %d/100. Found %d medium, %d low severity issues.",
			summary.RiskScore, summary.Medium, summary.Low)
	} else {
		scan.Status.Message = fmt.Sprintf("Scan completed. No issues found. Risk Score: %d/100.", summary.RiskScore)
	}

	if err := r.Status().Update(ctx, scan); err != nil {
		log.Error(err, "Failed to update YaraScan status")
		return ctrl.Result{}, err
	}

	log.Info("Image scan completed",
		"vulnerabilities", len(imageResult.Vulnerabilities),
		"secrets", len(imageResult.SecretsFound),
		"matches", matchCount,
		"riskScore", summary.RiskScore)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *YaraScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&yarav1alpha1.YaraScan{}).
		Complete(r)
}
