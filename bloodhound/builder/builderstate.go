package builder

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Macmod/flashingestor/core"
	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/Macmod/flashingestor/reader"
	"github.com/go-ldap/ldap/v3"
)

// Cache shards' constants - affects memory vs contention tradeoff
const (
	ShardNumStandard = 16 // Used for high-volume lookups (SIDs, DNs, hostnames)
	ShardNumSmall    = 2  // Used for lower-volume lookups (cert templates)
)

// State maintains global caches and mappings during BloodHound data construction.
// This is a singleton accessed via BState().
type State struct {
	DomainControllers      map[string][]TypedPrincipal  // Domain SID → DCs in that domain
	domainControllersMu    sync.RWMutex                 // Protects DomainControllers map writes
	AttrGUIDMap            sync.Map                     // Schema attribute name → GUID mappings
	DomainSIDCache         *SimpleCache                 // Domain name → SID
	SIDDomainCache         *SimpleCache                 // SID → domain name
	NetBIOSDomainCache     *SimpleCache                 // NetBIOS name → DNS domain name
	MemberCache            *StringCache                 // DN → Entry
	SIDCache               *StringCache                 // SID → Entry
	HostDnsCache           *StringCache                 // domain+hostname → Computer Entry
	SamCache               *StringCache                 // domain+sAMAccountName → Entry
	MachineSIDCache        *StringCache                 // Object SID → Entry with MachineSID
	ChildCache             *ParentChildCache            // Parent DN → Child Entries
	AdminSDHolderHashCache sync.Map                     // Domain → AdminSDHolder ACL hash
	CertTemplateCache      *StringCache                 // domain+template CN/OID → Cert Template Entry
	GPOCache               *GPOCache                    // DN → GPO metadata (for GPO local group processing)
	WellKnown              *WellKnownSIDTracker         // Seen well-known SIDs (S-1-5-32-*, etc)
	CacheWaitGroup         sync.WaitGroup               // Waitgroup for cache loading
	EmptySDCount           int                          // # of entries with empty security descriptors
	loadedCaches           map[string]bool              // Tracks which msgpack files have been loaded
	domainToForestMap      sync.Map                     // Domain → forest root mapping
	gpLinksCache           map[string]GPLinkEntry       // Cached gPLink+objectType for GPO collection (domains+OUs), keyed by DN
	computerDNMap          map[string]map[string]string // Cached computer SID by domain for GPO collection, keyed by domain -> DN
}

// GPLinkEntry stores gPLink and object type for domains/OUs
type GPLinkEntry struct {
	GPLink     string
	ObjectType string // "domain" or "ou"
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

// loadDomainToForestMap reads ForestDomains.json to establish domain→forest mappings.
// This is used to determine forest-level relationships during conversion.
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

// Init prepares the state for a new operation.
// This is called at the start of each remote collection and conversion operations.
func (st *State) Init(forestMapPath string) {
	if forestMapPath != "" {
		st.loadDomainToForestMap(forestMapPath)
	} else {
		st.domainToForestMap = sync.Map{}
	}

	st.EmptySDCount = 0

	// Initialize caches only if they don't exist
	if st.DomainSIDCache == nil {
		st.DomainSIDCache = NewSimpleCache()
	}

	if st.SIDDomainCache == nil {
		st.SIDDomainCache = NewSimpleCache()
	}

	if st.NetBIOSDomainCache == nil {
		st.NetBIOSDomainCache = NewSimpleCache()
	}

	if st.SIDCache == nil {
		st.SIDCache = NewCache(ShardNumStandard)
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

	if st.MachineSIDCache == nil {
		st.MachineSIDCache = NewCache(ShardNumStandard)
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

	if st.DomainControllers == nil {
		st.domainControllersMu.Lock()
		st.DomainControllers = make(map[string][]TypedPrincipal)
		st.domainControllersMu.Unlock()
	}

	if st.loadedCaches == nil {
		st.loadedCaches = make(map[string]bool)
	}

	if st.gpLinksCache == nil {
		st.gpLinksCache = make(map[string]GPLinkEntry)
	}

	if st.computerDNMap == nil {
		st.computerDNMap = make(map[string]map[string]string)
	}
}

// IsCacheLoaded checks if a msgpack file has already been loaded into caches.
// This prevents re-processing the same file multiple times.
func (st *State) IsCacheLoaded(fileName string) bool {
	_, exists := st.loadedCaches[fileName]
	return exists
}

// MarkCacheLoaded records that a msgpack file has been processed.
func (st *State) MarkCacheLoaded(fileName string) {
	st.loadedCaches[fileName] = true
}

// GetCachedGPLinks returns gPLink entries stored for GPO collection (domains and OUs), keyed by DN
func (st *State) GetCachedGPLinks() map[string]GPLinkEntry {
	return st.gpLinksCache
}

// GetCachedComputerDNMap returns computer SID map stored for GPO collection, keyed by domain then DN
func (st *State) GetCachedComputerDNMap() map[string]map[string]string {
	return st.computerDNMap
}

// CacheEntries reads LDAP entries from a msgpack file and populates multiple caches
// for efficient lookups during remote collection / conversion steps. Different entry types are cached
// in different ways based on the identifier (domains, users, computers, etc).
func (st *State) CacheEntries(reader *reader.MPReader, identifier string, logger *core.Logger, shouldAbort func() bool, progressCallback func(processed, total int)) error {
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

		resolvedEntry := resolveADEntry(entry)

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

		// Populate multiple caches for different lookup patterns:
		// - ChildCache: enables efficient "get all children of an OU/container" queries
		// - MemberCache: DN-based lookups for group membership resolution
		// - SIDCache: SID-based lookups (primary key for most BloodHound operations)
		parentDN := entry.GetParentDN()
		if parentDN != "" {
			st.ChildCache.AddChild(parentDN, &cacheEntry)
		}

		st.MemberCache.Set(entry.DN, &cacheEntry)
		st.SIDCache.Set(entry.GetSID(), &cacheEntry)

		sAMAccountName := entry.GetAttrVal("sAMAccountName", "")

		if identifier == "domains" || identifier == "ous" {
			// For GPOLocalGroup processing
			gpLink := entry.GetAttrVal("gPLink", "")

			// Skip entries without gPLink - they won't have GPO changes anyway
			// This deviates from the official implementation which always
			// fills AffectedComputers, but should be more lightweight
			if gpLink != "" {
				// Convert plural identifier to singular objectType
				objectType := identifier
				if identifier == "domains" {
					objectType = "domain"
				} else if identifier == "ous" {
					objectType = "ou"
				}

				st.gpLinksCache[originalEntry.DN] = GPLinkEntry{
					GPLink:     gpLink,
					ObjectType: objectType,
				}
			}
		}

		if identifier == "computers" {
			dnsHostname := entry.GetAttrVal("dNSHostName", "")
			if dnsHostname != "" {
				st.HostDnsCache.Set(domainName+"+"+dnsHostname, &cacheEntry)
			}

			if entry.IsDC() {
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

			// For GPOLocalGroup processing
			sid := entry.GetSID()
			domainName := entry.GetDomainFromDN()
			if sid != "" && domainName != "" {
				if st.computerDNMap[domainName] == nil {
					st.computerDNMap[domainName] = make(map[string]string)
				}
				dn := strings.ToUpper(entry.DN)
				st.computerDNMap[domainName][dn] = sid
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

			trustSid := gildap.ConvertSID(hex.EncodeToString(trustSidBytes))
			st.DomainSIDCache.Set(trustName, trustSid)
			st.SIDDomainCache.Set(trustSid, trustName)
		} else if identifier == "containers" {
			// Check if this is the AdminSDHolder container
			if strings.HasPrefix(strings.ToUpper(entry.DN), "CN=ADMINSDHOLDER,CN=SYSTEM,") {
				domainName := entry.GetDomainFromDN()

				securityDescriptor := entry.GetAttrRawVal("nTSecurityDescriptor", []byte{})
				if len(securityDescriptor) > 0 {
					// Calculate the implicit ACL hash
					aclHash, err := CalculateImplicitACLHash(securityDescriptor)
					if err != nil {
						logger.Log0("❌ Error calculating AdminSDHolder ACL hash for %s: %v", domainName, err)
					} else if aclHash != "" {
						// Store the hash indexed by domain name
						st.AdminSDHolderHashCache.Store(domainName, aclHash)
						logger.Log0(fmt.Sprintf("🔒 Cached AdminSDHolder ACL hash for domain \"%s\"", domainName))
					}
				}
			}
		} else if identifier == "configuration" {
			objectClasses := entry.GetAttrVals("objectClass", []string{})
			// Certificate templates can be referenced by CN or OID, so cache both
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

			// Parse crossRef objects in Partitions container to cache NetBIOS domain names
			if slices.Contains(objectClasses, "crossRef") {
				// systemFlags=3 indicates this crossRef represents an AD domain naming context
				systemFlags := entry.GetAttrVal("systemFlags", "")
				if systemFlags == "3" {
					netbiosName := entry.GetAttrVal("nETBIOSName", "")
					dnsRoot := entry.GetAttrVal("dnsRoot", "")
					if netbiosName != "" && dnsRoot != "" {
						st.NetBIOSDomainCache.Set(netbiosName, strings.ToUpper(dnsRoot))
					}
				}
			}
		} else if identifier == "gpos" {
			// For GPOLocalGroup processing
			gpcFileSysPath := entry.GetAttrVal("gPCFileSysPath", "")
			flags := entry.GetAttrVal("flags", "")

			if gpcFileSysPath != "" {
				st.GPOCache.Set(originalEntry.DN, &GPOCacheEntry{
					Name:    entry.GetAttrVal("displayName", ""),
					GUID:    entry.GetGUID(),
					GPOPath: gpcFileSysPath,
					Flags:   flags,
				})
			}
		}

		// sAMAccountName lookups are used extensively for user/computer/group resolution
		if sAMAccountName != "" {
			st.SamCache.Set(domainName+"+"+sAMAccountName, &cacheEntry)
		}
	}

	return nil
}

// Clear clears all cached data and resets the state
func (st *State) Clear() {
	st.domainControllersMu.Lock()
	st.DomainControllers = make(map[string][]TypedPrincipal, 0)
	st.domainControllersMu.Unlock()

	st.AttrGUIDMap = sync.Map{}

	st.AdminSDHolderHashCache = sync.Map{}

	st.DomainSIDCache = NewSimpleCache()
	st.SIDDomainCache = NewSimpleCache()
	st.NetBIOSDomainCache = NewSimpleCache()
	st.MemberCache = NewCache(ShardNumStandard)
	st.SIDCache = NewCache(ShardNumStandard)
	st.HostDnsCache = NewCache(ShardNumStandard)
	st.SamCache = NewCache(ShardNumStandard)
	st.MachineSIDCache = NewCache(ShardNumStandard)
	st.ChildCache = NewParentChildCache(ShardNumStandard)
	st.CertTemplateCache = NewCache(ShardNumSmall)
	st.GPOCache = NewGPOCache()
	st.loadedCaches = make(map[string]bool)

	st.gpLinksCache = make(map[string]GPLinkEntry)
	st.computerDNMap = make(map[string]map[string]string)
}

// resolveADEntry converts a raw LDAP entry into a BloodHound-compatible typed principal.
// It determines the object type (User, Computer, Group, OU, etc) and extracts the appropriate
// identifier (SID or GUID) and principal name based on AD object class and attributes.
func resolveADEntry(entry gildap.LDAPEntry) map[string]string {
	resolved := make(map[string]string)

	account := entry.GetAttrVal("sAMAccountName", "")
	dn := entry.DN

	var domain string
	if dn != "" {
		domain = entry.GetDomainFromDN()
	}

	objectClass := entry.GetAttrVals("objectClass", []string{})
	resolved["objectid"] = entry.GetSID()
	resolved["principal"] = strings.ToUpper(account + "@" + domain)

	if account == "" {
		// Objects without sAMAccountName: domains, OUs, containers, etc.
		// These use GUID as identifier instead of SID
		if slices.Contains(objectClass, "domain") {
			resolved["type"] = "Domain"
		} else if guidStr := entry.GetGUID(); guidStr != "" {
			resolved["objectid"] = strings.ToUpper(guidStr)
			name := entry.GetAttrVal("name", "")
			resolved["principal"] = strings.ToUpper(name + "@" + domain)

			if slices.Contains(objectClass, "organizationalUnit") {
				resolved["type"] = "OU"
			} else if slices.Contains(objectClass, "container") {
				resolved["type"] = "Container"
			} else {
				resolved["type"] = "Base"
			}
		} else {
			resolved["type"] = "Base"
		}
	} else {
		// Objects with sAMAccountName: users, computers, groups
		// Type is determined by sAMAccountType attribute
		accountTypeVal := entry.GetAttrVal("sAMAccountType", "")
		accountType, _ := strconv.Atoi(accountTypeVal)

		switch {
		case slices.Contains([]int{268435456, 268435457, 536870912, 536870913}, accountType):
			// Distribution/security groups (global/universal)
			resolved["type"] = "Group"
		case accountType == 805306368 ||
			slices.Contains(objectClass, "msDS-GroupManagedServiceAccount") ||
			slices.Contains(objectClass, "msDS-ManagedServiceAccount"):
			// User accounts (including gMSA/sMSA service accounts)
			resolved["type"] = "User"
		case accountType == 805306369:
			// Computer accounts
			resolved["type"] = "Computer"
			shortName := strings.TrimSuffix(account, "$")
			resolved["principal"] = strings.ToUpper(shortName + "." + domain)
		case accountType == 805306370:
			// Trust accounts
			resolved["type"] = "trustaccount"
		default:
			resolved["type"] = "Base"
		}
	}

	return resolved
}
