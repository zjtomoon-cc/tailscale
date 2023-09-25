// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"
	tsapi "tailscale.com/kube/apis/v1alpha1"
)

func TestSetConnectorCondition(t *testing.T) {
	cn := tsapi.Connector{}
	clock := &fakeclock.FakeClock{}
	fakeNow := metav1.NewTime(clock.Now())
	fakePast := metav1.NewTime(time.Now().Add(-5 * time.Minute))
	zl, err := zap.NewDevelopment()
	assert.Nil(t, err)

	// Set up a new condition
	SetConnectorCondition(&cn, tsapi.ConnectorReady, metav1.ConditionTrue, "someReason", "someMsg", 1, clock, zl.Sugar())
	assert.Equal(t, cn, tsapi.Connector{
		Status: tsapi.ConnectorStatus{
			Conditions: []tsapi.ConnectorCondition{
				{
					Type:               tsapi.ConnectorReady,
					Status:             metav1.ConditionTrue,
					Reason:             "someReason",
					Message:            "someMsg",
					ObservedGeneration: 1,
					LastTransitionTime: &fakeNow,
				},
			},
		},
	})

	// Modify status of an existing condition
	cn.Status = tsapi.ConnectorStatus{
		Conditions: []tsapi.ConnectorCondition{
			{
				Type:               tsapi.ConnectorReady,
				Status:             metav1.ConditionFalse,
				Reason:             "someReason",
				Message:            "someMsg",
				ObservedGeneration: 1,
				LastTransitionTime: &fakePast,
			},
		},
	}
	SetConnectorCondition(&cn, tsapi.ConnectorReady, metav1.ConditionTrue, "anotherReason", "anotherMsg", 2, clock, zl.Sugar())
	assert.Equal(t, cn, tsapi.Connector{
		Status: tsapi.ConnectorStatus{
			Conditions: []tsapi.ConnectorCondition{
				{
					Type:               tsapi.ConnectorReady,
					Status:             metav1.ConditionTrue,
					Reason:             "anotherReason",
					Message:            "anotherMsg",
					ObservedGeneration: 2,
					LastTransitionTime: &fakeNow,
				},
			},
		},
	})

	// Don't modify last transition time if status hasn't changed
	cn.Status = tsapi.ConnectorStatus{
		Conditions: []tsapi.ConnectorCondition{
			{
				Type:               tsapi.ConnectorReady,
				Status:             metav1.ConditionTrue,
				Reason:             "someReason",
				Message:            "someMsg",
				ObservedGeneration: 1,
				LastTransitionTime: &fakePast,
			},
		},
	}
	SetConnectorCondition(&cn, tsapi.ConnectorReady, metav1.ConditionTrue, "anotherReason", "anotherMsg", 2, clock, zl.Sugar())
	assert.Equal(t, cn, tsapi.Connector{
		Status: tsapi.ConnectorStatus{
			Conditions: []tsapi.ConnectorCondition{
				{
					Type:               tsapi.ConnectorReady,
					Status:             metav1.ConditionTrue,
					Reason:             "anotherReason",
					Message:            "anotherMsg",
					ObservedGeneration: 2,
					LastTransitionTime: &fakePast,
				},
			},
		},
	})

}
