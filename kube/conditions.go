// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

import (
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
	tsapi "tailscale.com/kube/apis/v1alpha1"
)

// SetConnectorCondition ensures that Connector status has a condition with the
// given attributes. LastTransitionTime gets set every time condition's status
// changes
func SetConnectorCondition(cn *tsapi.Connector, conditionType tsapi.ConnectorConditionType, status metav1.ConditionStatus, reason, message string, gen int64, clock clock.Clock, logger *zap.SugaredLogger) {
	newCondition := tsapi.ConnectorCondition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: gen,
	}

	nowTime := metav1.NewTime(clock.Now())
	newCondition.LastTransitionTime = &nowTime

	idx := slices.IndexFunc(cn.Status.Conditions, func(cond tsapi.ConnectorCondition) bool {
		return cond.Type == conditionType
	})

	if idx == -1 {
		cn.Status.Conditions = append(cn.Status.Conditions, newCondition)
		return
	}

	// Update the existing condition
	cond := cn.Status.Conditions[idx]
	// If this update doesn't contain a state transition, we don't update
	// the conditions LastTransitionTime to Now()
	if cond.Status == status {
		newCondition.LastTransitionTime = cond.LastTransitionTime
	} else {
		logger.Info("Status change for Connector condition %q from %q to %q", conditionType, cond.Status, status)
	}

	cn.Status.Conditions[idx] = newCondition
}

// RemoveConnectorCondition will remove condition of the given type
func RemoveConnectorCondition(conn *tsapi.Connector, conditionType tsapi.ConnectorConditionType) {
	conn.Status.Conditions = slices.DeleteFunc(conn.Status.Conditions, func(cond tsapi.ConnectorCondition) bool {
		return cond.Type == conditionType
	})
}
