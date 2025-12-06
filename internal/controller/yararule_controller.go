package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	yarav1alpha1 "github.com/yara-operator/yara-operator/api/v1alpha1"
	"github.com/yara-operator/yara-operator/internal/yara"
)

// YaraRuleReconciler reconciles a YaraRule object
type YaraRuleReconciler struct {
	client.Client
	Log         logr.Logger
	Scheme      *runtime.Scheme
	YaraScanner *yara.Scanner
}

// +kubebuilder:rbac:groups=yara.security.io,resources=yararules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=yara.security.io,resources=yararules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=yara.security.io,resources=yararules/finalizers,verbs=update

// Reconcile handles YaraRule reconciliation
func (r *YaraRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("yararule", req.NamespacedName)

	// Fetch the YaraRule instance
	var rule yarav1alpha1.YaraRule
	if err := r.Get(ctx, req.NamespacedName, &rule); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	log.Info("Reconciling YaraRule", "name", rule.Spec.Name)

	// Validate the YARA rule
	if err := r.YaraScanner.ValidateRule(rule.Spec.Content); err != nil {
		// Rule is invalid
		rule.Status.Phase = yarav1alpha1.PhaseInvalid
		rule.Status.Message = fmt.Sprintf("Rule validation failed: %v", err)
	} else {
		// Rule is valid
		rule.Status.Phase = yarav1alpha1.PhaseValid
		rule.Status.Message = "Rule is valid"
	}

	now := ctrl.Now()
	rule.Status.LastValidated = &now.Time

	// Update status
	if err := r.Status().Update(ctx, &rule); err != nil {
		log.Error(err, "Failed to update YaraRule status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: time.Hour}, nil
}

// SetupWithManager sets up the controller with the Manager
func (r *YaraRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&yarav1alpha1.YaraRule{}).
		Complete(r)
}

