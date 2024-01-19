// Copyright The Shipwright Contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1beta1

import (
	"context"

	"github.com/shipwright-io/build/pkg/apis/build/v1alpha1"
	"github.com/shipwright-io/build/pkg/ctxlog"
	"github.com/shipwright-io/build/pkg/webhook"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	runtime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"
)

// ensure v1beta1 implements the Conversion interface
var _ webhook.Conversion = (*BuildRun)(nil)

// To Alpha
func (src *BuildRun) ConvertTo(ctx context.Context, obj *unstructured.Unstructured) error {
	ctxlog.Debug(ctx, "Converting BuildRun from beta to alpha", "namespace", src.Namespace, "name", src.Name)

	var alphaBuildRun v1alpha1.BuildRun

	alphaBuildRun.TypeMeta = src.TypeMeta
	alphaBuildRun.TypeMeta.APIVersion = alphaGroupVersion
	alphaBuildRun.ObjectMeta = src.ObjectMeta

	// BuildRunSpec BuildSpec
	if src.Spec.Build.Build != nil {
		newBuildSpec := v1alpha1.BuildSpec{}
		if err := src.Spec.Build.Build.ConvertTo(&newBuildSpec); err != nil {
			return err
		}
		alphaBuildRun.Spec.BuildSpec = &newBuildSpec
	} else if src.Spec.Build.Name != nil {
		alphaBuildRun.Spec.BuildRef = &v1alpha1.BuildRef{
			Name: *src.Spec.Build.Name,
		}
	}

	// BuildRunSpec Sources
	if src.Spec.Source != nil && src.Spec.Source.Type == LocalType && src.Spec.Source.LocalSource != nil {
		alphaBuildRun.Spec.Sources = append(alphaBuildRun.Spec.Sources, v1alpha1.BuildSource{
			Name:    src.Spec.Source.LocalSource.Name,
			Type:    v1alpha1.LocalCopy,
			Timeout: src.Spec.Source.LocalSource.Timeout,
		})
	}

	// BuildRunSpec ServiceAccount
	// With the deprecation of serviceAccount.Generate, serviceAccount is set to ".generate" to have the SA created on fly.
	if src.Spec.ServiceAccount != nil && *src.Spec.ServiceAccount == ".generate" {
		alphaBuildRun.Spec.ServiceAccount = &v1alpha1.ServiceAccount{
			Name:     &src.ObjectMeta.Name,
			Generate: pointer.Bool(true),
		}
	} else {
		alphaBuildRun.Spec.ServiceAccount = &v1alpha1.ServiceAccount{
			Name: src.Spec.ServiceAccount,
		}
	}

	// BuildRunSpec Timeout
	alphaBuildRun.Spec.Timeout = src.Spec.Timeout

	// BuildRunSpec ParamValues
	alphaBuildRun.Spec.ParamValues = nil
	for _, p := range src.Spec.ParamValues {
		param := v1alpha1.ParamValue{}
		p.convertToAlpha(&param)
		alphaBuildRun.Spec.ParamValues = append(alphaBuildRun.Spec.ParamValues, param)
	}

	// BuildRunSpec Image

	if src.Spec.Output != nil {
		alphaBuildRun.Spec.Output = &v1alpha1.Image{
			Image:       src.Spec.Output.Image,
			Annotations: src.Spec.Output.Annotations,
			Labels:      src.Spec.Output.Labels,
		}
		if src.Spec.Output.PushSecret != nil {
			alphaBuildRun.Spec.Output.Credentials = &corev1.LocalObjectReference{
				Name: *src.Spec.Output.PushSecret,
			}
		}
		if src.Spec.Output.VulnerabilityScan != nil {
			alphaBuildRun.Spec.Output.VulnerabilityScan = &v1alpha1.VulnerabilityScanOptions{
				Enabled:  src.Spec.Output.VulnerabilityScan.Enabled,
				FailPush: src.Spec.Output.VulnerabilityScan.FailPush,
			}
			if src.Spec.Output.VulnerabilityScan.IgnoreOptions != nil {
				alphaBuildRun.Spec.Output.VulnerabilityScan.IgnoreOptions = &v1alpha1.VulnerabilityIgnoreOptions{
					Issues:   src.Spec.Output.VulnerabilityScan.IgnoreOptions.Issues,
					Severity: src.Spec.Output.VulnerabilityScan.IgnoreOptions.Severity,
					Unfixed:  src.Spec.Output.VulnerabilityScan.IgnoreOptions.Unfixed,
				}
			}
		}
	}

	// BuildRunSpec State
	alphaBuildRun.Spec.State = (*v1alpha1.BuildRunRequestedState)(src.Spec.State)

	// BuildRunSpec Env
	alphaBuildRun.Spec.Env = src.Spec.Env

	// BuildRunSpec Retention
	alphaBuildRun.Spec.Retention = (*v1alpha1.BuildRunRetention)(src.Spec.Retention)

	// BuildRunSpec Volumes
	alphaBuildRun.Spec.Volumes = []v1alpha1.BuildVolume{}
	for _, vol := range src.Spec.Volumes {
		alphaBuildRun.Spec.Volumes = append(alphaBuildRun.Spec.Volumes, v1alpha1.BuildVolume{
			Name:         vol.Name,
			VolumeSource: vol.VolumeSource,
		})
	}

	mapito, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&alphaBuildRun)
	if err != nil {
		ctxlog.Error(ctx, err, "failed structuring the newObject")
	}
	obj.Object = mapito

	return nil

}

// From Alpha
func (src *BuildRun) ConvertFrom(ctx context.Context, obj *unstructured.Unstructured) error {

	var alphaBuildRun v1alpha1.BuildRun

	unstructured := obj.UnstructuredContent()
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructured, &alphaBuildRun)
	if err != nil {
		ctxlog.Error(ctx, err, "failed unstructuring the buildrun convertedObject")
	}

	ctxlog.Debug(ctx, "Converting BuildRun from alpha to beta", "namespace", alphaBuildRun.Namespace, "name", alphaBuildRun.Name)

	src.ObjectMeta = alphaBuildRun.ObjectMeta
	src.TypeMeta = alphaBuildRun.TypeMeta
	src.TypeMeta.APIVersion = betaGroupVersion

	src.Spec.ConvertFrom(&alphaBuildRun.Spec)

	var sourceStatus *SourceResult
	for _, s := range alphaBuildRun.Status.Sources {
		sourceStatus = &SourceResult{
			Git:         (*GitSourceResult)(s.Git),
			OciArtifact: (*OciArtifactSourceResult)(s.Bundle),
		}
	}

	conditions := []Condition{}

	for _, c := range alphaBuildRun.Status.Conditions {
		ct := Condition{
			Type:               Type(c.Type),
			Status:             c.Status,
			LastTransitionTime: c.LastTransitionTime,
			Reason:             c.Reason,
			Message:            c.Message,
		}
		conditions = append(conditions, ct)
	}

	if alphaBuildRun.Status.FailureDetails != nil {
		src.Status.FailureDetails = &FailureDetails{
			Reason:   alphaBuildRun.Status.FailureDetails.Reason,
			Message:  alphaBuildRun.Status.FailureDetails.Message,
			Location: (*Location)(alphaBuildRun.Status.FailureDetails.Location),
		}
	}

	var output *Output
	if alphaBuildRun.Status.Output != nil {
		output = &Output{
			Digest: alphaBuildRun.Status.Output.Digest,
			Size:   alphaBuildRun.Status.Output.Size,
		}
		for _, vuln := range alphaBuildRun.Status.Output.Vulnerabilities {
			output.Vulnerabilities = append(output.Vulnerabilities, Vulnerability{
				VulnerabilityID: vuln.VulnerabilityID,
				Severity:        vuln.Severity,
			})
		}
	}

	src.Status = BuildRunStatus{
		Source:         sourceStatus,
		Output:         output,
		Conditions:     conditions,
		TaskRunName:    alphaBuildRun.Status.LatestTaskRunRef,
		StartTime:      alphaBuildRun.Status.StartTime,
		CompletionTime: alphaBuildRun.Status.CompletionTime,
		FailureDetails: src.Status.FailureDetails,
	}

	buildBeta := Build{}
	if alphaBuildRun.Status.BuildSpec != nil {
		buildBeta.Spec.ConvertFrom(alphaBuildRun.Status.BuildSpec)
		src.Status.BuildSpec = &buildBeta.Spec
	}

	return nil
}

func (dest *BuildRunSpec) ConvertFrom(orig *v1alpha1.BuildRunSpec) error {

	// BuildRunSpec BuildSpec
	if orig.BuildSpec != nil {
		dest.Build.Build = &BuildSpec{}
		dest.Build.Build.ConvertFrom(orig.BuildSpec)
	}
	if orig.BuildRef != nil {
		dest.Build.Name = &orig.BuildRef.Name
	}

	// only interested on spec.sources as long as an item of the list
	// is of the type LocalCopy. Otherwise, we move into bundle or git types.
	index, isLocal := v1alpha1.IsLocalCopyType(orig.Sources)
	if isLocal {
		dest.Source = &BuildRunSource{
			Type: LocalType,
			LocalSource: &Local{
				Name:    orig.Sources[index].Name,
				Timeout: orig.Sources[index].Timeout,
			},
		}
	}

	if orig.ServiceAccount != nil {
		dest.ServiceAccount = orig.ServiceAccount.Name
	}

	dest.Timeout = orig.Timeout

	// BuildRunSpec ParamValues
	dest.ParamValues = []ParamValue{}
	for _, p := range orig.ParamValues {
		param := convertBetaParamValue(p)
		dest.ParamValues = append(dest.ParamValues, param)
	}

	// Handle BuildRunSpec Output
	if orig.Output != nil {
		dest.Output = &Image{
			Image:       orig.Output.Image,
			Annotations: orig.Output.Annotations,
			Labels:      orig.Output.Labels,
		}

		if orig.Output.Credentials != nil {
			dest.Output.PushSecret = &orig.Output.Credentials.Name
		}

		if orig.Output.VulnerabilityScan != nil {
			dest.Output.VulnerabilityScan = &VulnerabilityScanOptions{
				Enabled:  orig.Output.VulnerabilityScan.Enabled,
				FailPush: orig.Output.VulnerabilityScan.FailPush,
			}
			if orig.Output.VulnerabilityScan.IgnoreOptions != nil {
				dest.Output.VulnerabilityScan.IgnoreOptions = &VulnerabilityIgnoreOptions{
					Issues:   orig.Output.VulnerabilityScan.IgnoreOptions.Issues,
					Severity: orig.Output.VulnerabilityScan.IgnoreOptions.Severity,
					Unfixed:  orig.Output.VulnerabilityScan.IgnoreOptions.Unfixed,
				}
			}
		}

	}

	// BuildRunSpec State
	dest.State = (*BuildRunRequestedState)(orig.State)

	// BuildRunSpec Env
	dest.Env = orig.Env

	// BuildRunSpec Retention
	dest.Retention = (*BuildRunRetention)(orig.Retention)

	// BuildRunSpec Volumes
	dest.Volumes = []BuildVolume{}
	for _, vol := range orig.Volumes {
		dest.Volumes = append(dest.Volumes, BuildVolume{
			Name:         vol.Name,
			VolumeSource: vol.VolumeSource,
		})
	}
	return nil
}
