// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"tailscale.com/kube"
	tsapi "tailscale.com/kube/apis/v1alpha1"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
)

const (
	reasonSubnetRouterCreationFailed    = "SubnetRouterCreationFailed"
	reasonSubnetRouterCreated           = "SubnetRouterCreated"
	reasonSubnetRouterCleanupFailed     = "SubnetRouterCleanupFailed"
	reasonSubnetRouterCleanupInProgress = "SubnetRouterCleanupInProgress"

	messageSubnetRouterCreationFailed = "Failed creating subnet router for routes %s: %v"
	messageSubnetRouterCreated        = "Created subnet router for routes %s"
	messageSubnetRouterCleanupFailed  = "Failed cleaning up subnet router resources: %v"
	msgSubnetRouterCleanupInProgress  = "SubnetRouterCleanupInProgress"

	shortRequeue = time.Second * 5
)

type ConnectorReconciler struct {
	client.Client

	recorder record.EventRecorder
	ssr      *tailscaleSTSReconciler
	logger   *zap.SugaredLogger

	tsnamespace string

	clock clock.Clock

	mu sync.Mutex // protects following

	// A Connector can only have a single subnet router (because I cannot
	// think why there would be a need for multiple in a cluster). However,
	// we do not enforce a Connector to be a singleton (there is no
	// straightforward way to do that in kube) and I cannot think of any
	// potential issues if multiple Connectors with subnet routers were
	// created. So, in theory, there could be multiple subnet routers in a
	// cluster.
	subnetRouters set.Slice[types.UID]
}

var (
	// gaugeIngressResources tracks the number of subnet routers that we're
	// currently managing.
	gaugeSubnetRouterResources = clientmetric.NewGauge("k8s_subnet_router_resources")
)

func (a *ConnectorReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := a.logger.With("connector", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	cn := new(tsapi.Connector)
	err = a.Get(ctx, req.NamespacedName, cn)
	if apierrors.IsNotFound(err) {
		logger.Debugf("connector not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get tailscale.io Connector: %w", err)
	}
	if !cn.DeletionTimestamp.IsZero() {
		logger.Debugf("connector is being deleted or should not be exposed, cleaning up components")
		ix := slices.Index(cn.Finalizers, FinalizerName)
		if ix < 0 {
			logger.Debugf("no finalizer, nothing to do")
			return reconcile.Result{}, nil
		}
		// At the momement SubnetRouter is the only component configurable via
		// ConnectorSpec and a ConnectorSpec without a SubnetRouter is invalid- but
		// that will change in the future - so run the cleanup and provision
		// conditionally already.
		if cn.Spec.SubnetRouter != nil {

			if done, err := a.maybeCleanupSubnetRouter(ctx, logger, cn); err != nil {
				return reconcile.Result{}, err
			} else if !done {
				logger.Debugf("cleanup not finished, will retry...")
				return reconcile.Result{RequeueAfter: shortRequeue}, nil
			}
		}

		cn.Finalizers = append(cn.Finalizers[:ix], cn.Finalizers[ix+1:]...)
		if err := a.Update(ctx, cn); err != nil {
			return reconcile.Result{}, err
		}
		logger.Infof("connector resources cleaned up")
		return reconcile.Result{}, nil
	}

	oldCnStatus := cn.Status.DeepCopy()
	defer func() {
		if cn.Status.SubnetRouter == nil {
			kube.SetConnectorCondition(cn, tsapi.ConnectorReady, metav1.ConditionUnknown, "", "", cn.Generation, a.clock, logger)
		} else if cn.Status.SubnetRouter.Ready == metav1.ConditionTrue {
			kube.SetConnectorCondition(cn, tsapi.ConnectorReady, metav1.ConditionTrue, reasonSubnetRouterCreated, reasonSubnetRouterCreated, cn.Generation, a.clock, logger)
		} else {
			kube.SetConnectorCondition(cn, tsapi.ConnectorReady, metav1.ConditionFalse, cn.Status.SubnetRouter.Reason, cn.Status.SubnetRouter.Reason, cn.Generation, a.clock, logger)
		}
		if !apiequality.Semantic.DeepEqual(oldCnStatus, cn.Status) {
			// an error encountered here should get returned by the Reconcile function
			if updateErr := a.Client.Status().Update(ctx, cn); updateErr != nil {
				err = updateErr
			}
		}

	}()

	if !slices.Contains(cn.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("ensuring connector is set up")
		cn.Finalizers = append(cn.Finalizers, FinalizerName)
		if err := a.Update(ctx, cn); err != nil {
			err = fmt.Errorf("failed to add finalizer: %w", err)
			logger.Errorf("error adding finalizer: %v", err)
			return reconcile.Result{}, err
		}
	}

	// At the momement SubnetRouter is the only component configurable via
	// ConnectorSpec and a ConnectorSpec without a SubnetRouter is invalid- but
	// that will change in the future - so run the cleanup and provision
	// conditionally.
	if cn.Spec.SubnetRouter != nil && len(cn.Spec.SubnetRouter.Routes) > 0 {
		var sb strings.Builder
		sb.WriteString(string(cn.Spec.SubnetRouter.Routes[0]))
		for _, r := range cn.Spec.SubnetRouter.Routes[1:] {
			sb.WriteString(fmt.Sprintf(",%s", r))
		}
		cidrsS := sb.String()
		logger.Debugf("ensuring a subnet router is deployed")
		err := a.maybeProvisionSubnetRouter(ctx, logger, cn, cidrsS)
		if err != nil {
			msg := fmt.Sprintf(messageSubnetRouterCreationFailed, cidrsS, err)
			cn.Status.SubnetRouter = &tsapi.SubnetRouterStatus{
				Ready:   metav1.ConditionFalse,
				Reason:  reasonSubnetRouterCreationFailed,
				Message: msg,
			}
			a.recorder.Eventf(cn, corev1.EventTypeWarning, reasonSubnetRouterCreationFailed, msg)
			return reconcile.Result{}, err
		} else {
			cn.Status.SubnetRouter = &tsapi.SubnetRouterStatus{
				Routes:  cidrsS,
				Ready:   metav1.ConditionTrue,
				Reason:  reasonSubnetRouterCreated,
				Message: fmt.Sprintf(messageSubnetRouterCreated, cidrsS),
			}
		}

	} else {
		logger.Debugf("ensuring a subnet router is cleaned up if it was ever created")
		if done, err := a.maybeCleanupSubnetRouter(ctx, logger, cn); err != nil {
			msg := fmt.Sprintf(messageSubnetRouterCleanupFailed, err)
			cn.Status.SubnetRouter = &tsapi.SubnetRouterStatus{
				Routes:  "",
				Ready:   metav1.ConditionUnknown,
				Reason:  reasonSubnetRouterCleanupFailed,
				Message: msg,
			}
			a.recorder.Eventf(cn, corev1.EventTypeWarning, reasonSubnetRouterCleanupFailed, msg)
			return reconcile.Result{}, err
		} else if !done {
			logger.Debugf("cleanup not done yet, will retry...")
			cn.Status.SubnetRouter = &tsapi.SubnetRouterStatus{
				Routes:  "",
				Ready:   metav1.ConditionUnknown,
				Reason:  reasonSubnetRouterCleanupInProgress,
				Message: msgSubnetRouterCleanupInProgress,
			}
			return reconcile.Result{Requeue: true}, nil

		} else {
			cn.Status.SubnetRouter = &tsapi.SubnetRouterStatus{}
		}
	}

	return reconcile.Result{}, nil
}

func (a *ConnectorReconciler) maybeCleanupSubnetRouter(ctx context.Context, logger *zap.SugaredLogger, cn *tsapi.Connector) (bool, error) {
	if done, err := a.ssr.Cleanup(ctx, logger, childResourceLabels(cn.Name, a.tsnamespace, "subnetrouter")); err != nil {
		return false, fmt.Errorf("failed to cleanup: %w", err)
	} else if !done {
		logger.Debugf("cleanup not done yet, waiting for next reconcile")
		return false, nil
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("cleaned up subnet router")
	a.mu.Lock()
	defer a.mu.Unlock()
	a.subnetRouters.Remove(cn.UID)
	gaugeSubnetRouterResources.Set(int64(a.subnetRouters.Len()))
	return true, nil
}

// maybeProvisionSubnetRouter maybe deploys subnet router that exposes a subset of cluster cidrs to the tailnet
func (a *ConnectorReconciler) maybeProvisionSubnetRouter(ctx context.Context, logger *zap.SugaredLogger, cn *tsapi.Connector, cidrs string) error {
	if cn.Spec.SubnetRouter == nil || len(cn.Spec.SubnetRouter.Routes) < 1 {
		return nil
	}
	a.mu.Lock()
	a.subnetRouters.Add(cn.UID)
	gaugeSubnetRouterResources.Set(int64(a.subnetRouters.Len()))
	a.mu.Unlock()

	// TODO (irbekrm): there should be multiple pods that can use the same
	// Tailscale API key - is this possible?
	// TODO (irbekrm): we should allow users to apply scaling policies to
	// the subnet router- the oprator should not override changes to replica
	// count etc
	crl := childResourceLabels(cn.Name, a.tsnamespace, "subnetrouter")
	hostname, err := nameForSubnetRouter(cn)
	if err != nil {
		return err
	}
	sts := &tailscaleSTSConfig{
		ParentResourceName: cn.Name,
		ParentResourceUID:  string(cn.UID),
		// TODO (irbekrm): probably we don't want a single hostname for
		// the STS as there will be multiple pods
		Hostname:            hostname,
		ChildResourceLabels: crl,
		Routes:              cidrs,
	}
	if cn.Spec.SubnetRouter.Tag != "" {
		sts.Tags = []string{string(cn.Spec.SubnetRouter.Tag)}
	}

	_, err = a.ssr.Provision(ctx, logger, sts)

	return err
}

func nameForSubnetRouter(cn *tsapi.Connector) (string, error) {
	if h, ok := cn.Annotations[AnnotationHostname]; ok {
		if err := dnsname.ValidLabel(h); err != nil {
			return "", fmt.Errorf("invalid Tailscale hostname %q: %w", h, err)
		}
		return h, nil
	}
	return cn.Name + "-" + "subnetrouter", nil
}
