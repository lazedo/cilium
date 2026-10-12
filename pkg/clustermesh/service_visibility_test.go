// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/source"
)

type fakeVisibilityIPCache struct {
	identities map[string]ipcache.Identity
	metadata   map[string]*ipcache.K8sMetadata
}

func newFakeVisibilityIPCache() *fakeVisibilityIPCache {
	return &fakeVisibilityIPCache{
		identities: make(map[string]ipcache.Identity),
		metadata:   make(map[string]*ipcache.K8sMetadata),
	}
}

func (f *fakeVisibilityIPCache) Upsert(ip string, _ net.IP, _ uint8, meta *ipcache.K8sMetadata, id ipcache.Identity) (bool, error) {
	if cur, ok := f.identities[ip]; ok && !source.AllowOverwrite(cur.Source, id.Source) {
		return false, errors.New("overwrite not allowed")
	}
	f.identities[ip] = id
	f.metadata[ip] = meta
	return false, nil
}

func (f *fakeVisibilityIPCache) Delete(ip string, src source.Source) bool {
	if cur, ok := f.identities[ip]; ok && cur.Source == src {
		delete(f.identities, ip)
		delete(f.metadata, ip)
	}
	return false
}

func (f *fakeVisibilityIPCache) LookupByIP(ip string) (ipcache.Identity, bool) {
	id, ok := f.identities[ip]
	return id, ok
}

func (f *fakeVisibilityIPCache) GetK8sMetadata(ip netip.Addr) *ipcache.K8sMetadata {
	return f.metadata[ip.String()]
}

// endpoint adds a remote endpoint, as the IPIdentityWatcher would.
func (f *fakeVisibilityIPCache) endpoint(ip string, id identity.NumericIdentity, workload string) {
	f.identities[ip] = ipcache.Identity{ID: id, Source: source.ClusterMesh}
	meta := &ipcache.K8sMetadata{Namespace: "test", PodName: ip}
	if workload != "" {
		meta.Workload = &ipcache.K8sWorkload{Name: workload, Kind: "Deployment"}
	}
	f.metadata[ip] = meta
}

func (f *fakeVisibilityIPCache) requireAttributed(t *testing.T, ip string, id identity.NumericIdentity, workload string) {
	t.Helper()

	got, ok := f.identities[ip]
	require.True(t, ok, "frontend %s is not attributed", ip)
	require.Equal(t, source.ClusterMeshVisibility, got.Source)
	require.Equal(t, id, got.ID)

	want := &ipcache.K8sMetadata{Namespace: "test"}
	if workload != "" {
		want.Workload = &ipcache.K8sWorkload{Name: workload, Kind: "Deployment"}
	}
	require.Equal(t, want, f.metadata[ip])
}

func (f *fakeVisibilityIPCache) requireNotAttributed(t *testing.T, ip string) {
	t.Helper()

	got, ok := f.identities[ip]
	require.False(t, ok && got.Source == source.ClusterMeshVisibility, "frontend %s is attributed", ip)
}

var (
	echoID  = identity.NumericIdentity(2<<16 | 1234)
	otherID = identity.NumericIdentity(3<<16 | 4321)
)

func visibilityService(cluster, name string, frontends []string, backends ...string) *serviceStore.ClusterService {
	svc := serviceStore.NewClusterService(name, "test")
	svc.Cluster = cluster
	svc.VisibilityOnly = true
	svc.Frontends = make(map[string]serviceStore.PortConfiguration)
	for _, fe := range frontends {
		svc.Frontends[fe] = serviceStore.PortConfiguration{}
	}
	for _, be := range backends {
		svc.Backends[be] = serviceStore.PortConfiguration{}
	}
	return &svc
}

func TestServiceVisibilityAttribution(t *testing.T) {
	ipc := newFakeVisibilityIPCache()
	sv := newServiceVisibility(hivetest.Logger(t), ipc)

	ipc.endpoint("10.244.1.1", echoID, "echo")
	ipc.endpoint("10.244.1.2", echoID, "echo")

	svc := visibilityService("cluster2", "echo", []string{"10.97.0.10", "172.18.255.200"}, "10.244.1.1", "10.244.1.2")
	sv.OnUpdate(svc)

	// Both the ClusterIP and the load balancer address get the backends identity.
	ipc.requireAttributed(t, "10.97.0.10", echoID, "echo")
	ipc.requireAttributed(t, "172.18.255.200", echoID, "echo")

	// Removing the service removes the attribution.
	sv.OnDelete(svc)
	ipc.requireNotAttributed(t, "10.97.0.10")
	ipc.requireNotAttributed(t, "172.18.255.200")
}

func TestServiceVisibilityRequiresOneIdentity(t *testing.T) {
	ipc := newFakeVisibilityIPCache()
	sv := newServiceVisibility(hivetest.Logger(t), ipc)

	ipc.endpoint("10.244.1.1", echoID, "echo")
	ipc.endpoint("10.244.1.2", otherID, "other")
	ipc.endpoint("10.244.1.3", identity.ReservedIdentityRemoteNode, "")

	// Backends with different identities.
	sv.OnUpdate(visibilityService("cluster2", "mixed", []string{"10.97.0.10"}, "10.244.1.1", "10.244.1.2"))
	ipc.requireNotAttributed(t, "10.97.0.10")

	// A backend with a reserved identity, such as a host network pod.
	sv.OnUpdate(visibilityService("cluster2", "host", []string{"10.97.0.11"}, "10.244.1.3"))
	ipc.requireNotAttributed(t, "10.97.0.11")

	// No backends.
	sv.OnUpdate(visibilityService("cluster2", "empty", []string{"10.97.0.12"}))
	ipc.requireNotAttributed(t, "10.97.0.12")
}

func TestServiceVisibilityLateBackends(t *testing.T) {
	ipc := newFakeVisibilityIPCache()
	sv := newServiceVisibility(hivetest.Logger(t), ipc)

	// The service arrives before the identity of its backend.
	sv.OnUpdate(visibilityService("cluster2", "echo", []string{"10.97.0.10"}, "10.244.1.1"))
	ipc.requireNotAttributed(t, "10.97.0.10")

	// The periodic resync picks it up.
	ipc.endpoint("10.244.1.1", echoID, "echo")
	sv.reconcile()
	ipc.requireAttributed(t, "10.97.0.10", echoID, "echo")

	// And notices when the backend identity changes.
	ipc.endpoint("10.244.1.1", otherID, "other")
	sv.reconcile()
	ipc.requireAttributed(t, "10.97.0.10", otherID, "other")
}

func TestServiceVisibilityWorkload(t *testing.T) {
	ipc := newFakeVisibilityIPCache()
	sv := newServiceVisibility(hivetest.Logger(t), ipc)

	// Same identity, but the backends belong to different workloads.
	ipc.endpoint("10.244.1.1", echoID, "echo-a")
	ipc.endpoint("10.244.1.2", echoID, "echo-b")

	sv.OnUpdate(visibilityService("cluster2", "echo", []string{"10.97.0.10"}, "10.244.1.1", "10.244.1.2"))
	ipc.requireAttributed(t, "10.97.0.10", echoID, "")
}

func TestServiceVisibilityConflicts(t *testing.T) {
	ipc := newFakeVisibilityIPCache()
	sv := newServiceVisibility(hivetest.Logger(t), ipc)

	ipc.endpoint("10.244.1.1", echoID, "echo")
	ipc.endpoint("10.245.1.1", otherID, "other")

	// Two clusters announce the same load balancer address.
	a := visibilityService("cluster2", "echo", []string{"10.97.0.10", "172.18.255.200"}, "10.244.1.1")
	b := visibilityService("cluster3", "other", []string{"10.98.0.10", "172.18.255.200"}, "10.245.1.1")
	sv.OnUpdate(a)
	sv.OnUpdate(b)

	ipc.requireAttributed(t, "10.97.0.10", echoID, "echo")
	ipc.requireAttributed(t, "10.98.0.10", otherID, "other")
	ipc.requireNotAttributed(t, "172.18.255.200")

	// Once only one cluster claims it, it is attributed.
	sv.OnDelete(b)
	ipc.requireAttributed(t, "172.18.255.200", echoID, "echo")
	ipc.requireNotAttributed(t, "10.98.0.10")
}

func TestServiceVisibilityDoesNotOverrideEndpoints(t *testing.T) {
	ipc := newFakeVisibilityIPCache()
	sv := newServiceVisibility(hivetest.Logger(t), ipc)

	ipc.endpoint("10.244.1.1", echoID, "echo")
	// The frontend address belongs to an actual endpoint.
	ipc.endpoint("10.97.0.10", otherID, "other")

	svc := visibilityService("cluster2", "echo", []string{"10.97.0.10"}, "10.244.1.1")
	sv.OnUpdate(svc)
	require.Equal(t, ipcache.Identity{ID: otherID, Source: source.ClusterMesh}, ipc.identities["10.97.0.10"])

	// Nor removes them when the service goes away.
	sv.OnDelete(svc)
	require.Equal(t, ipcache.Identity{ID: otherID, Source: source.ClusterMesh}, ipc.identities["10.97.0.10"])
}

type recordingObserver struct {
	updates, deletes []string
}

func (r *recordingObserver) OnUpdate(key store.Key) {
	r.updates = append(r.updates, key.GetKeyName())
}

func (r *recordingObserver) OnDelete(key store.NamedKey) {
	r.deletes = append(r.deletes, key.GetKeyName())
}

func TestServiceVisibilityObserver(t *testing.T) {
	ipc := newFakeVisibilityIPCache()
	sv := newServiceVisibility(hivetest.Logger(t), ipc)
	shared := &recordingObserver{}
	obs := &serviceVisibilityObserver{shared: shared, visibility: sv}

	ipc.endpoint("10.244.1.1", echoID, "echo")
	svc := visibilityService("cluster2", "echo", []string{"10.97.0.10"}, "10.244.1.1")

	// Visibility-only services are tracked, and still forwarded.
	obs.OnUpdate(&serviceStore.ValidatingClusterService{ClusterService: *svc})
	ipc.requireAttributed(t, "10.97.0.10", echoID, "echo")
	require.Equal(t, []string{"cluster2/test/echo"}, shared.updates)

	// A service which becomes shared is load-balanced locally: no attribution.
	shared.updates = nil
	svc.VisibilityOnly, svc.Shared = false, true
	obs.OnUpdate(&serviceStore.ValidatingClusterService{ClusterService: *svc})
	ipc.requireNotAttributed(t, "10.97.0.10")
	require.Equal(t, []string{"cluster2/test/echo"}, shared.updates)

	// Deletions reach both.
	svc.VisibilityOnly, svc.Shared = true, false
	obs.OnUpdate(&serviceStore.ValidatingClusterService{ClusterService: *svc})
	ipc.requireAttributed(t, "10.97.0.10", echoID, "echo")
	obs.OnDelete(&serviceStore.ValidatingClusterService{ClusterService: *svc})
	ipc.requireNotAttributed(t, "10.97.0.10")
	require.Equal(t, []string{"cluster2/test/echo"}, shared.deletes)
}
