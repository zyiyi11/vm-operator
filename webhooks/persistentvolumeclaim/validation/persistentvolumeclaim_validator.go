// Copyright (c) 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlmgr "sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/vmware-tanzu/vm-operator/pkg/builder"
	pkgcfg "github.com/vmware-tanzu/vm-operator/pkg/config"
	pkgctx "github.com/vmware-tanzu/vm-operator/pkg/context"
	"github.com/vmware-tanzu/vm-operator/pkg/providers/vsphere/constants"
	"github.com/vmware-tanzu/vm-operator/pkg/topology"
	"github.com/vmware-tanzu/vm-operator/webhooks/common"
)

const (
	webHookName = "default"

	operationNotAllowedOnPVC = "%s operation on PVC with instance storage label is not allowed"
	addingISLabelNotAllowed  = "adding instance storage label is not allowed"
	invalidZone              = "cannot use zone that is being deleted"
)

var (
	labelPath                            = field.NewPath("metadata", "labels").Key(constants.InstanceStorageLabelKey)
	annotationPath                       = field.NewPath("metadata", "annotation")
	allowedAccountsForInstanceStoragePVC = map[string]struct{}{
		"system:serviceaccount:kube-system:persistent-volume-binder":     {},
		"system:serviceaccount:kube-system:pvc-protection-controller":    {},
		"system:serviceaccount:kube-system:generic-garbage-collector":    {},
		"system:serviceaccount:kube-system:namespace-controller":         {},
		"system:serviceaccount:vmware-system-csi:vsphere-csi-controller": {},
	}
)

// +kubebuilder:webhook:verbs=create;update;delete,path=/default-validate--v1-persistentvolumeclaim,mutating=false,failurePolicy=fail,groups="",resources=persistentvolumeclaims,versions=v1,name=default.validating.persistentvolumeclaim.vmoperator.vmware.com,sideEffects=None,admissionReviewVersions=v1

// AddToManager adds the webhook to the provided manager.
func AddToManager(ctx *pkgctx.ControllerManagerContext, mgr ctrlmgr.Manager) error {
	hook, err := builder.NewValidatingWebhook(ctx, mgr, webHookName, NewValidator(mgr.GetClient()))
	if err != nil {
		return fmt.Errorf("failed to create PersistentVolumeClaim validation webhook: %w", err)
	}
	mgr.GetWebhookServer().Register(hook.Path, hook)

	return nil
}

// NewValidator returns the package's Validator.
func NewValidator(client client.Client) builder.Validator {
	return validator{
		client: client,
		// TODO BMV Use the Context.scheme instead
		converter: runtime.DefaultUnstructuredConverter,
	}
}

type validator struct {
	client    client.Client
	converter runtime.UnstructuredConverter
}

// vmFromUnstructured returns the VirtualMachine from the unstructured object.
func (v validator) pvcFromUnstructured(obj runtime.Unstructured) (*corev1.PersistentVolumeClaim, error) {
	pvc := &corev1.PersistentVolumeClaim{}
	if err := v.converter.FromUnstructured(obj.UnstructuredContent(), pvc); err != nil {
		return nil, err
	}
	return pvc, nil
}

func (v validator) For() schema.GroupVersionKind {
	return corev1.SchemeGroupVersion.WithKind(reflect.TypeOf(corev1.PersistentVolumeClaim{}).Name())
}

func (v validator) validateSpecifyZone(ctx *pkgctx.WebhookRequestContext, pvc *corev1.PersistentVolumeClaim) field.ErrorList {
	var fieldErrs field.ErrorList

	volumeRequestedTopologies, err := getVolumeRequestedTopologyFromPVCAnnotation(pvc)
	if err != nil {
		return append(fieldErrs, field.Invalid(annotationPath, pvc.Annotations, err.Error()))
	}
	if volumeRequestedTopologies == nil {
		return fieldErrs
	}
	for _, topo := range volumeRequestedTopologies {
		if zoneName, ok := topo[constants.AnnGuestClusterRequestedTopology]; ok {
			zone, err := topology.GetZone(ctx.Context, v.client, zoneName, pvc.Namespace)
			if err != nil {
				return append(fieldErrs, field.Invalid(annotationPath, pvc.Name, err.Error()))
			}
			//  when deletion of a Zone is initiated, deletionTimestamp is set.
			if !zone.DeletionTimestamp.IsZero() {
				return append(fieldErrs, field.Invalid(annotationPath, pvc.Name, invalidZone))
			}
		}
	}
	return fieldErrs
}

/* NOTE: If the user is privileged user, the request will not be validated.*/

func (v validator) ValidateCreate(ctx *pkgctx.WebhookRequestContext) admission.Response {
	if isPrivilegedAccountForISPVC(ctx) {
		return common.BuildValidationResponse(ctx, nil, nil, nil)
	}

	var fieldErrs field.ErrorList
	if isInstanceStorageLabelPresent(ctx.Obj.GetLabels()) {
		fieldErrs = append(fieldErrs, field.Forbidden(labelPath,
			fmt.Sprintf(operationNotAllowedOnPVC, admissionv1.Create)))
	}
	if pkgcfg.FromContext(ctx).Features.WorkloadDomainIsolation {
		pvc, err := v.pvcFromUnstructured(ctx.Obj)
		if err != nil {
			return webhook.Errored(http.StatusBadRequest, err)
		}
		fieldErrs = append(fieldErrs, v.validateSpecifyZone(ctx, pvc)...)
	}
	return common.BuildValidationResponse(ctx, nil, convertToStringArray(fieldErrs), nil)
}

func (v validator) ValidateDelete(ctx *pkgctx.WebhookRequestContext) admission.Response {
	if isPrivilegedAccountForISPVC(ctx) {
		return common.BuildValidationResponse(ctx, nil, nil, nil)
	}

	var fieldErrs field.ErrorList
	if isInstanceStorageLabelPresent(ctx.Obj.GetLabels()) {
		fieldErrs = append(fieldErrs, field.Forbidden(labelPath,
			fmt.Sprintf(operationNotAllowedOnPVC, admissionv1.Delete)))
	}

	return common.BuildValidationResponse(ctx, nil, convertToStringArray(fieldErrs), nil)
}

func (v validator) ValidateUpdate(ctx *pkgctx.WebhookRequestContext) admission.Response {
	if isPrivilegedAccountForISPVC(ctx) {
		return common.BuildValidationResponse(ctx, nil, nil, nil)
	}
	var fieldErrs field.ErrorList
	// If instance storage labels already exists for resource, do not allow update resource
	if isInstanceStorageLabelPresent(ctx.OldObj.GetLabels()) {
		fieldErrs = append(fieldErrs, field.Forbidden(labelPath,
			fmt.Sprintf(operationNotAllowedOnPVC, admissionv1.Update)))
	} else if isInstanceStorageLabelPresent(ctx.Obj.GetLabels()) {
		fieldErrs = append(fieldErrs, field.Forbidden(labelPath, addingISLabelNotAllowed))
	}

	return common.BuildValidationResponse(ctx, nil, convertToStringArray(fieldErrs), nil)
}

// isInstanceStorageLabelPresent - returns true/false depending on presence of instance storage label.
func isInstanceStorageLabelPresent(labels map[string]string) bool {
	_, isLabelPresent := labels[constants.InstanceStorageLabelKey]
	return isLabelPresent
}

// convertToStringArray converts field.ErrorList to array of strings.
func convertToStringArray(fieldErrs field.ErrorList) []string {
	validationErrs := make([]string, 0, len(fieldErrs))
	for _, fieldErr := range fieldErrs {
		validationErrs = append(validationErrs, fieldErr.Error())
	}
	return validationErrs
}

// isPrivilegedAccountForISPVC returns true if requested user is privileged to add/modify/delete instance storage PVCs
// As PVC is kubernetes native object, it is managed by few kube system service accounts.
// For instance storage PVC apart from kube system service accounts we also allow
// kube-admin and vm-operator's pod service account to manage these PVCs
// more info - https://kubernetes.io/docs/concepts/storage/persistent-volumes/#lifecycle-of-a-volume-and-claim
// TODO: Dynamically get service accounts which manages PVC.
func isPrivilegedAccountForISPVC(ctx *pkgctx.WebhookRequestContext) bool {
	// ctx.IsPrivilegedAccount returns true is requested user is kube-admin or vm-operator's pods system account.
	if ctx.IsPrivilegedAccount {
		return true
	}

	if _, ok := allowedAccountsForInstanceStoragePVC[ctx.UserInfo.Username]; ok {
		return true
	}

	return false
}

// getVolumeAccessibleTopologyFromPVCAnnotation returns requested topologies generated using
// PVC annotation "csi.vsphere.volume-requested-topology".
func getVolumeRequestedTopologyFromPVCAnnotation(pvc *corev1.PersistentVolumeClaim) ([]map[string]string, error) {
	volumeRequestedTopology := pvc.Annotations[constants.AnnGuestClusterRequestedTopology]
	if volumeRequestedTopology == "" {
		return nil, nil
	}
	volumeRequestedTopologyArr := make([]map[string]string, 0)
	err := json.Unmarshal([]byte(volumeRequestedTopology), &volumeRequestedTopologyArr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse annotation: %q value %v from the claim: %q, namespace: %q. "+
			"err: %v", constants.AnnGuestClusterRequestedTopology, volumeRequestedTopology,
			pvc.Name, pvc.Namespace, err)
	}
	return volumeRequestedTopologyArr, nil
}