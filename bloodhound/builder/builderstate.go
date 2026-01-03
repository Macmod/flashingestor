package builder

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"

	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/Macmod/flashingestor/reader"
	"github.com/go-ldap/ldap/v3"
)

// Cache shards' constants
const (
	ShardNumStandard = 16 // Standard number of shards
	ShardNumSmall    = 2  // Smaller number of shards
)

// State maintains global caches and mappings during BloodHound data construction.
// This is a singleton accessed via BState().
type State struct {
	DomainControllers      map[string][]TypedPrincipal // Map of domain SID -> list of DCs
	domainControllersMu    sync.RWMutex                // Protects DomainControllers
	AttrGUIDMap            sync.Map                    // Thread-safe map[string]string
	DomainSIDCache         *SimpleCache
	SIDDomainCache         *SimpleCache
	MemberCache            *StringCache
	SIDCache               *StringCache
	HostDnsCache           *StringCache
	SamCache               *StringCache
	ChildCache             *ParentChildCache
	AdminSDHolderHashCache sync.Map // Thread-safe map[string]string
	CertTemplateCache      *StringCache
	GPOCache               *GPOCache
	WellKnown              *WellKnownSIDTracker
	CacheWaitGroup         sync.WaitGroup
	EmptySDCount           int
	loadedCaches           map[string]bool
	domainToForestMap      sync.Map
}

var bState *State
var once sync.Once

// BState returns the singleton State instance.
func BState() *State {
	if bState == nil {
		once.Do(func() {
			bState = &State{}
		})
	}

	return bState
}

func (st *State) GetForestRoot(domain string) string {
	if forestRoot, ok := st.domainToForestMap.Load(domain); ok {
		return forestRoot.(string)
	}

	return ""
}

func (st *State) loadDomainToForestMap(path string) {
	st.domainToForestMap = sync.Map{}

	file, err := os.Open(path)
	if err != nil {
		return // File doesn't exist or can't be opened
	}
	defer file.Close()

	var forestMap map[string]string
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&forestMap); err != nil {
		return // Failed to decode JSON
	}

	for domain, forestRoot := range forestMap {
		st.domainToForestMap.Store(domain, forestRoot)
	}
}

func (st *State) Init(forestMapPath string) {
	if forestMapPath != "" {
		st.loadDomainToForestMap(forestMapPath)
	} else {
		st.domainToForestMap = sync.Map{}
	}

	st.AttrGUIDMap = sync.Map{}

	st.EmptySDCount = 0

	if st.DomainSIDCache == nil {
		st.DomainSIDCache = NewSimpleCache()
	}

	if st.SIDDomainCache == nil {
		st.SIDDomainCache = NewSimpleCache()
	}

	if st.SIDCache == nil {
		st.SIDCache = NewCache(ShardNumStandard)
	}

	if st.DomainControllers == nil {
		st.DomainControllers = make(map[string][]TypedPrincipal)
	}

	if st.MemberCache == nil {
		st.MemberCache = NewCache(ShardNumStandard)
	}

	if st.HostDnsCache == nil {
		st.HostDnsCache = NewCache(ShardNumStandard)
	}

	if st.SamCache == nil {
		st.SamCache = NewCache(ShardNumStandard)
	}

	if st.ChildCache == nil {
		st.ChildCache = NewParentChildCache(ShardNumStandard)
	}

	if st.CertTemplateCache == nil {
		st.CertTemplateCache = NewCache(ShardNumSmall)
	}

	if st.GPOCache == nil {
		st.GPOCache = NewGPOCache()
	}

	if st.WellKnown == nil {
		st.WellKnown = NewWellKnownSIDTracker()
	}

	if st.loadedCaches == nil {
		st.loadedCaches = make(map[string]bool)
	}
}

func (st *State) IsCacheLoaded(fileName string) bool {
	_, exists := st.loadedCaches[fileName]
	return exists
}

func (st *State) MarkCacheLoaded(fileName string) {
	st.loadedCaches[fileName] = true
}

func (st *State) CacheEntries(reader *reader.MPReader, identifier string, log chan<- string, shouldAbort func() bool, progressCallback func(processed, total int)) error {
	processedCount := 0

	originalEntry := new(ldap.Entry)
	var entry gildap.LDAPEntry

	localTotal := reader.Length()
	for i := 0; i < localTotal; i++ {
		if shouldAbort != nil && shouldAbort() {
			return fmt.Errorf("aborted")
		}

		processedCount++
		if progressCallback != nil {
			progressCallback(processedCount, localTotal)
		}

		*originalEntry = ldap.Entry{}
		err := reader.ReadEntry(originalEntry)
		if err != nil {
			continue
		}

		// Process!
		entry.Init(originalEntry)

		domainName := entry.GetDomainFromDN()

		resolvedEntry := ResolveADEntry(entry)

		/* TODO: Review this part */
		if resolvedEntry["objectid"] == "" {
			//fmt.Fprintf(os.Stderr, "Missing objectid for entry: %s from file %s\n", entry.DN, fileName)
			continue
		}

		var cacheEntry Entry
		cacheEntry.FromTypedPrincipal(&TypedPrincipal{
			ObjectIdentifier: resolvedEntry["objectid"],
			ObjectType:       resolvedEntry["type"],
		})

		// Cache entry in both ChildCache and MemberCache
		// ChildCache => Resolves all children of a DN efficiently
		// MemberCache => Resolves a single entry by its DN
		// SID cache => Resolves a single entry by its SID
		parentDN := entry.GetParentDN()
		if parentDN != "" {
			st.ChildCache.AddChild(parentDN, &cacheEntry)
		}

		st.MemberCache.Set(entry.DN, &cacheEntry)
		st.SIDCache.Set(entry.GetSID(), &cacheEntry)

		if identifier == "computers" {
			dnsHostname := entry.GetAttrVal("dNSHostName", "")
			if dnsHostname != "" {
				st.HostDnsCache.Set(domainName+"+"+dnsHostname, &cacheEntry)
			}

			if entry.IsDC() {
				// Get domain SID from entry
				domainSID, err := entry.GetDomainSID()
				if err == nil && domainSID != "" {
					st.domainControllersMu.Lock()
					if st.DomainControllers[domainSID] == nil {
						st.DomainControllers[domainSID] = make([]TypedPrincipal, 0)
					}
					st.DomainControllers[domainSID] = append(st.DomainControllers[domainSID], TypedPrincipal{
						ObjectIdentifier: entry.GetSID(),
						ObjectType:       "computer",
					})
					st.domainControllersMu.Unlock()
				}
			}
		} else if identifier == "domains" {
			domainSID := entry.GetSID()

			// Cache domain name <-> SID mappings
			st.DomainSIDCache.Set(domainName, domainSID)
			st.SIDDomainCache.Set(domainSID, domainName)
		} else if identifier == "trusts" {
			// For trusts, cache the trust SID as well
			trustName := strings.ToUpper(entry.GetAttrVal("cn", ""))
			trustSidBytes := entry.GetAttrRawVal("securityIdentifier", []byte{})
			var trustSid string
			if len(trustSidBytes) == 0 {
				trustSid = ""
			}

			trustSid = gildap.ConvertSID(hex.EncodeToString(trustSidBytes))
			st.DomainSIDCache.Set(trustName, trustSid)
			st.SIDDomainCache.Set(trustSid, trustName)
		} else if identifier == "containers" {
			// Check if this is the AdminSDHolder container
			if strings.HasPrefix(strings.ToUpper(entry.DN), "CN=ADMINSDHOLDER,CN=SYSTEM,") {
				// Get the domain name from the entry's DN
				domainName := entry.GetDomainFromDN()

				// Get the security descriptor
				securityDescriptor := entry.GetAttrRawVal("nTSecurityDescriptor", []byte{})
				if len(securityDescriptor) > 0 {
					// Calculate the implicit ACL hash
					aclHash, err := CalculateImplicitACLHash(securityDescriptor)
					if err != nil {
						log <- fmt.Sprintf("❌ Error calculating AdminSDHolder ACL hash for %s: %v", domainName, err)
					} else if aclHash != "" {
						// Store the hash indexed by domain name
						st.AdminSDHolderHashCache.Store(domainName, aclHash)
						log <- fmt.Sprintf("🔒 Cached AdminSDHolder ACL hash for domain \"%s\"", domainName)
					}
				}
			}
		} else if identifier == "configuration" {
			objectClasses := entry.GetAttrVals("objectClass", []string{})
			// Cache cert template CN to GUID mapping before building
			if slices.Contains(objectClasses, "pKICertificateTemplate") {
				cn := entry.GetAttrVal("cn", "")
				oid := entry.GetAttrVal("msPKI-Cert-Template-OID", "")
				objectGUID := entry.GetGUID()
				if (cn != "" || oid != "") && objectGUID != "" {
					var cacheEntry Entry
					cacheEntry.FromTypedPrincipal(&TypedPrincipal{
						ObjectIdentifier: objectGUID,
						ObjectType:       "CertTemplate",
					})
					st.CertTemplateCache.Set(domainName+"+"+cn, &cacheEntry)
					st.CertTemplateCache.Set(domainName+"+"+oid, &cacheEntry)
				}
			}
		}

		sAMAccountName := entry.GetAttrVal("sAMAccountName", "")
		if sAMAccountName != "" {
			st.SamCache.Set(domainName+"+"+sAMAccountName, &cacheEntry)
		}
	}

	return nil
}

// ClearCache clears all cached data and resets the state
func (st *State) Clear() {
	st.domainControllersMu.Lock()
	st.DomainControllers = make(map[string][]TypedPrincipal, 0)
	st.domainControllersMu.Unlock()

	st.AttrGUIDMap = sync.Map{}

	st.AdminSDHolderHashCache = sync.Map{}

	st.DomainSIDCache = NewSimpleCache()
	st.SIDDomainCache = NewSimpleCache()
	st.MemberCache = NewCache(ShardNumStandard)
	st.SIDCache = NewCache(ShardNumStandard)
	st.HostDnsCache = NewCache(ShardNumStandard)
	st.SamCache = NewCache(ShardNumStandard)
	st.ChildCache = NewParentChildCache(ShardNumStandard)
	st.CertTemplateCache = NewCache(ShardNumSmall)
	st.GPOCache = NewGPOCache()
	st.loadedCaches = make(map[string]bool)
}
