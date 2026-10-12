// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/source"
)

// ServiceVisibilityConfig configures the attribution of the frontends of the
// services that remote clusters export for visibility.
type ServiceVisibilityConfig struct {
	// ClusterMeshServiceVisibility attributes the frontends of the services
	// that remote clusters export for visibility to the identity of their
	// backends.
	ClusterMeshServiceVisibility bool `mapstructure:"clustermesh-service-visibility"`
}

// DefaultServiceVisibilityConfig attributes the remote frontends unless opted
// out.
var DefaultServiceVisibilityConfig = ServiceVisibilityConfig{
	ClusterMeshServiceVisibility: true,
}

func (def ServiceVisibilityConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("clustermesh-service-visibility", def.ClusterMeshServiceVisibility,
		"Attribute the frontends of the services that remote clusters export for visibility "+
			"to the identity of their backends")
}

// ServiceVisibilityIPCache is the subset of the IPCache used to attribute the
// frontends of remote services.
type ServiceVisibilityIPCache interface {
	Upsert(ip string, hostIP net.IP, hostKey uint8, k8sMeta *ipcache.K8sMetadata, newIdentity ipcache.Identity) (bool, error)
	Delete(ip string, source source.Source) (namedPortsChanged bool)
	LookupByIP(ip string) (ipcache.Identity, bool)
	GetK8sMetadata(ip netip.Addr) *ipcache.K8sMetadata
}

// serviceVisibilityResync is the interval at which the attribution is
// recomputed, to pick up the backends whose identity became known after their
// service.
const serviceVisibilityResync = 15 * time.Second

// serviceVisibility attributes the frontends of the services that remote
// clusters export for visibility to the identity of their backends. The
// traffic towards such a frontend is load-balanced in the remote cluster, and
// would otherwise be seen as world by the policies and by Hubble.
//
// A frontend is attributed only when all the backends of its service are known
// and share the same identity, which is neither reserved nor local. It is left
// alone when remote clusters disagree on it.
type serviceVisibility struct {
	log     *slog.Logger
	ipcache ServiceVisibilityIPCache

	mu lock.Mutex
	// services are the visibility-only services, indexed by cluster/namespace/name.
	services map[string]*serviceStore.ClusterService
	// attributed are the frontends currently upserted in the IPCache.
	attributed map[string]frontendAttribution

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type frontendAttribution struct {
	id   identity.NumericIdentity
	meta *ipcache.K8sMetadata
}

func (a frontendAttribution) equal(o frontendAttribution) bool {
	return a.id == o.id && a.meta.Equal(o.meta)
}

func newServiceVisibility(log *slog.Logger, ipc ServiceVisibilityIPCache) *serviceVisibility {
	return &serviceVisibility{
		log:        log,
		ipcache:    ipc,
		services:   make(map[string]*serviceStore.ClusterService),
		attributed: make(map[string]frontendAttribution),
	}
}

// Start implements cell.HookInterface.
func (sv *serviceVisibility) Start(cell.HookContext) error {
	ctx, cancel := context.WithCancel(context.Background())
	sv.cancel = cancel

	sv.wg.Add(1)
	go func() {
		defer sv.wg.Done()

		ticker := time.NewTicker(serviceVisibilityResync)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sv.reconcile()
			}
		}
	}()
	return nil
}

// Stop implements cell.HookInterface.
func (sv *serviceVisibility) Stop(cell.HookContext) error {
	if sv.cancel != nil {
		sv.cancel()
	}
	sv.wg.Wait()
	return nil
}

// OnUpdate records a visibility-only service and recomputes the attribution.
func (sv *serviceVisibility) OnUpdate(svc *serviceStore.ClusterService) {
	cp := *svc

	sv.mu.Lock()
	sv.services[svc.String()] = &cp
	sv.mu.Unlock()

	sv.reconcile()
}

// OnDelete forgets a service and recomputes the attribution if it was known.
func (sv *serviceVisibility) OnDelete(svc *serviceStore.ClusterService) {
	sv.mu.Lock()
	_, found := sv.services[svc.String()]
	delete(sv.services, svc.String())
	sv.mu.Unlock()

	if found {
		sv.reconcile()
	}
}

// reconcile brings the IPCache in line with the attribution derived from the
// known services and from the current identity of their backends.
func (sv *serviceVisibility) reconcile() {
	sv.mu.Lock()
	defer sv.mu.Unlock()

	desired := make(map[string]frontendAttribution)
	conflicting := make(map[string]struct{})
	for _, svc := range sv.services {
		attr, ok := sv.attribute(svc)
		if !ok {
			continue
		}

		for frontend := range svc.Frontends {
			addr, err := netip.ParseAddr(frontend)
			if err != nil {
				continue
			}

			key := addr.String()
			if _, ok := conflicting[key]; ok {
				continue
			}
			if prev, ok := desired[key]; ok && !prev.equal(attr) {
				delete(desired, key)
				conflicting[key] = struct{}{}
				continue
			}
			desired[key] = attr
		}
	}

	for frontend := range sv.attributed {
		if _, ok := desired[frontend]; !ok {
			sv.ipcache.Delete(frontend, source.ClusterMeshVisibility)
			delete(sv.attributed, frontend)
		}
	}

	for frontend, attr := range desired {
		if cur, ok := sv.attributed[frontend]; ok && cur.equal(attr) {
			continue
		}

		_, err := sv.ipcache.Upsert(frontend, nil, 0, attr.meta, ipcache.Identity{
			ID:     attr.id,
			Source: source.ClusterMeshVisibility,
		})
		if err != nil {
			// The address is owned by a source describing an actual endpoint.
			sv.log.Debug("Not attributing remote service frontend",
				logfields.IPAddr, frontend,
				logfields.Identity, attr.id,
				logfields.Error, err,
			)
			delete(sv.attributed, frontend)
			continue
		}
		sv.attributed[frontend] = attr
	}
}

// attribute returns the identity shared by all the backends of the service,
// along with the namespace of the service and the workload shared by the
// backends, if any.
func (sv *serviceVisibility) attribute(svc *serviceStore.ClusterService) (frontendAttribution, bool) {
	if len(svc.Backends) == 0 {
		return frontendAttribution{}, false
	}

	var (
		id           identity.NumericIdentity
		workload     *ipcache.K8sWorkload
		sameWorkload = true
		first        = true
	)
	for backend := range svc.Backends {
		addr, err := netip.ParseAddr(backend)
		if err != nil {
			return frontendAttribution{}, false
		}

		backendID, ok := sv.ipcache.LookupByIP(addr.String())
		if !ok || backendID.Source == source.ClusterMeshVisibility ||
			backendID.ID.IsReservedIdentity() || backendID.ID.HasLocalScope() {
			return frontendAttribution{}, false
		}

		var backendWorkload *ipcache.K8sWorkload
		if meta := sv.ipcache.GetK8sMetadata(addr); meta != nil {
			backendWorkload = meta.Workload
		}

		if first {
			id, workload, first = backendID.ID, backendWorkload, false
			continue
		}
		if backendID.ID != id {
			return frontendAttribution{}, false
		}
		if !sameK8sWorkload(workload, backendWorkload) {
			sameWorkload = false
		}
	}

	meta := &ipcache.K8sMetadata{Namespace: svc.Namespace}
	if sameWorkload && workload != nil {
		meta.Workload = &ipcache.K8sWorkload{Name: workload.Name, Kind: workload.Kind}
	}
	return frontendAttribution{id: id, meta: meta}, true
}

func sameK8sWorkload(a, b *ipcache.K8sWorkload) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// serviceVisibilityObserver forwards the events about the services of a remote
// cluster to the observer of the shared services, and also tracks the
// visibility-only ones.
type serviceVisibilityObserver struct {
	shared     store.Observer
	visibility *serviceVisibility
}

// OnUpdate implements store.Observer.
func (o *serviceVisibilityObserver) OnUpdate(key store.Key) {
	o.shared.OnUpdate(key)

	svc := &(key.(*serviceStore.ValidatingClusterService).ClusterService)
	if svc.VisibilityOnly {
		o.visibility.OnUpdate(svc)
	} else {
		// The service may have been shared since.
		o.visibility.OnDelete(svc)
	}
}

// OnDelete implements store.Observer.
func (o *serviceVisibilityObserver) OnDelete(key store.NamedKey) {
	o.shared.OnDelete(key)

	svc := &(key.(*serviceStore.ValidatingClusterService).ClusterService)
	o.visibility.OnDelete(svc)
}
