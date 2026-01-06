package builder

import (
	"strings"
	"sync"

	gildap "github.com/Macmod/flashingestor/ldap"
)

// WellKnownSIDTracker tracks well-known SIDs and which ones have been seen
type WellKnownSIDTracker struct {
	sids map[string]gildap.WksDesc
	seen map[string]bool
	mu   sync.RWMutex
}

// NewWellKnownSIDTracker creates a new tracker with the well-known SIDs
func NewWellKnownSIDTracker() *WellKnownSIDTracker {
	return &WellKnownSIDTracker{
		sids: gildap.GetWellKnownSIDsData(),
		seen: make(map[string]bool),
	}
}

// Get retrieves a well-known SID and marks it as seen
func (w *WellKnownSIDTracker) Get(sid string) (gildap.WksDesc, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	desc, ok := w.sids[sid]
	if ok {
		w.seen[sid] = true
	}
	return desc, ok
}

// IsSeenWellKnownPrincipal checks if a SID has been marked as seen
func (w *WellKnownSIDTracker) IsSeenWellKnownPrincipal(sid string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.seen[sid]
}

// GetAll returns all well-known SIDs (for iteration purposes, does not mark as seen)
func (w *WellKnownSIDTracker) GetAll() map[string]gildap.WksDesc {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Return a copy to prevent concurrent map access issues
	result := make(map[string]gildap.WksDesc, len(w.sids))
	for k, v := range w.sids {
		result[k] = v
	}
	return result
}

// GetSeen returns only the well-known SIDs that have been marked as seen
func (w *WellKnownSIDTracker) GetSeen() map[string]gildap.WksDesc {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Return only seen SIDs
	result := make(map[string]gildap.WksDesc)
	for sid := range w.seen {
		if desc, ok := w.sids[sid]; ok {
			result[sid] = desc
		}
	}
	return result
}

// BuildWellKnownGroup creates a well-known group object for BloodHound
func BuildWellKnownGroup(sid, name string, domainName string, domainSID string) WellKnownGroup {
	members := []TypedPrincipal{}

	// Enterprise Domain Controllers group includes all DCs from this domain
	if name == "Enterprise Domain Controllers" && domainName != "" {
		BState().domainControllersMu.RLock()
		dcs, ok := BState().DomainControllers[domainSID]
		BState().domainControllersMu.RUnlock()
		if ok {
			members = append(members, dcs...)
		}
	}

	return WellKnownGroup{
		BaseADObject: BaseADObject{
			ObjectIdentifier: domainName + "-" + sid,
			Aces:             []ACE{},
			IsDeleted:        false,
			IsACLProtected:   false,
			ContainedBy:      nil,
		},
		Properties: WellKnownProperties{
			BaseProperties: BaseProperties{
				Domain:    domainName,
				DomainSID: domainSID,
			},
			Name: strings.ToUpper(name) + "@" + strings.ToUpper(domainName),
		},
		Members: members,
	}
}

// BuildWellKnownUser creates a well-known user object for BloodHound
func BuildWellKnownUser(sid, name string, domainName string, domainSID string) WellKnownUser {
	return WellKnownUser{
		BaseADObject: BaseADObject{
			ObjectIdentifier: domainName + "-" + sid,
			Aces:             []ACE{},
			IsDeleted:        false,
			IsACLProtected:   false,
			ContainedBy:      nil,
		},
		Properties: WellKnownProperties{
			BaseProperties: BaseProperties{
				Domain:    domainName,
				DomainSID: domainSID,
			},
			Name: strings.ToUpper(name) + "@" + strings.ToUpper(domainName),
		},
	}
}
