// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/ipcache"
)

func TestResolveEndpointPodMetadata(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	newIPGetter := func(meta *ipcache.K8sMetadata) *testutils.FakeIPGetter {
		return &testutils.FakeIPGetter{
			OnGetK8sMetadata: func(netip.Addr) *ipcache.K8sMetadata {
				return meta
			},
			OnLookupSecIDByIP: func(netip.Addr) (ipcache.Identity, bool) {
				return ipcache.Identity{}, false
			},
		}
	}

	t.Run("remote endpoint", func(t *testing.T) {
		resolver := NewEndpointResolver(hivetest.Logger(t), nil, nil, newIPGetter(&ipcache.K8sMetadata{
			Namespace: "remote-namespace",
			PodName:   "remote-pod",
			Workload: &ipcache.K8sWorkload{
				Name: "remote-workload",
				Kind: "Deployment",
			},
		}))

		endpoint := resolver.ResolveEndpoint(ip, 0, DatapathContext{})

		assert.Equal(t, "remote-namespace", endpoint.GetNamespace())
		assert.Equal(t, "remote-pod", endpoint.GetPodName())
		assert.Equal(t, []*flowpb.Workload{{Name: "remote-workload", Kind: "Deployment"}}, endpoint.GetWorkloads())
	})

	t.Run("remote endpoint without workload", func(t *testing.T) {
		resolver := NewEndpointResolver(hivetest.Logger(t), nil, nil, newIPGetter(&ipcache.K8sMetadata{
			Namespace: "remote-namespace",
			PodName:   "remote-pod",
		}))

		endpoint := resolver.ResolveEndpoint(ip, 0, DatapathContext{})

		assert.Empty(t, endpoint.GetWorkloads())
	})
}
