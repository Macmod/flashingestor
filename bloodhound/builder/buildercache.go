package builder

import (
	"strings"
	"sync"
)

// Entry represents a cached typed principal with its object identifier and type.
type Entry struct {
	ObjectIdentifier string
	ObjectTypeRaw    ObjectTypeEnum
}

func (e *Entry) FromTypedPrincipal(r *TypedPrincipal) {
	e.ObjectIdentifier = r.ObjectIdentifier

	objTypeRaw, _ := StrToObjectTypeRawMap[r.ObjectType]
	e.ObjectTypeRaw = objTypeRaw
}

func (e *Entry) ToTypedPrincipal() TypedPrincipal {
	objTypeStr, _ := ObjectTypeRawToStrMap[e.ObjectTypeRaw]

	return TypedPrincipal{
		ObjectIdentifier: e.ObjectIdentifier,
		ObjectType:       objTypeStr,
	}
}

// ParentChildCache maintains parent-child relationships in AD containers
// using sharded concurrent maps for scalability.
type ParentChildCache struct {
	shards []parentShard
	mask   uint64
}

type parentShard struct {
	mu sync.RWMutex
	m  map[uint64][]Entry // Maps parent DN hash to slice of child objects
}

// NewParentChildCache creates a sharded cache for parent-child relationships.
// The number of shards is rounded up to the next power of 2.
func NewParentChildCache(numShards int) *ParentChildCache {
	if numShards <= 0 {
		numShards = 16
	}
	// Round up to next power of 2
	n := 1
	for n < numShards {
		n <<= 1
	}
	c := &ParentChildCache{
		shards: make([]parentShard, n),
		mask:   uint64(n - 1),
	}
	for i := range c.shards {
		c.shards[i].m = make(map[uint64][]Entry)
	}
	return c
}

func (c *ParentChildCache) shardFor(h uint64) *parentShard {
	return &c.shards[h&c.mask]
}

// AddChild adds a child object to the specified parent DN.
func (c *ParentChildCache) AddChild(parentDN string, child *Entry) {
	h := GetHash(parentDN)
	s := c.shardFor(h)
	s.mu.Lock()
	s.m[h] = append(s.m[h], *child)
	s.mu.Unlock()
}

// SetChildren sets all children for a parent DN (replaces existing).
func (c *ParentChildCache) SetChildren(parentDN string, children []Entry) {
	h := GetHash(parentDN)
	s := c.shardFor(h)
	s.mu.Lock()
	s.m[h] = make([]Entry, len(children))
	copy(s.m[h], children)
	s.mu.Unlock()
}

// GetChildren retrieves all direct children for a parent DN.
func (c *ParentChildCache) GetChildren(parentDN string) ([]Entry, bool) {
	h := GetHash(parentDN)
	s := c.shardFor(h)
	s.mu.RLock()
	children, ok := s.m[h]
	if !ok {
		s.mu.RUnlock()
		return nil, false
	}
	// Return a copy to avoid race conditions
	result := make([]Entry, len(children))
	copy(result, children)
	s.mu.RUnlock()
	return result, true
}

// HasChildren checks if a parent DN has any children without returning them.
func (c *ParentChildCache) HasChildren(parentDN string) bool {
	h := GetHash(parentDN)
	s := c.shardFor(h)
	s.mu.RLock()
	children, ok := s.m[h]
	hasChildren := ok && len(children) > 0
	s.mu.RUnlock()
	return hasChildren
}

// Delete removes all children for a parent DN.
func (c *ParentChildCache) Delete(parentDN string) {
	h := GetHash(parentDN)
	s := c.shardFor(h)
	s.mu.Lock()
	delete(s.m, h)
	s.mu.Unlock()
}

// Size returns the approximate number of parent entries.
func (c *ParentChildCache) Size() int {
	total := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		total += len(s.m)
		s.mu.RUnlock()
	}
	return total
}

// TotalChildren returns the approximate total number of child objects across all parents.
func (c *ParentChildCache) TotalChildren() int {
	total := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		for _, children := range s.m {
			total += len(children)
		}
		s.mu.RUnlock()
	}
	return total
}

// StringCache is a concurrent sharded map keyed by xxhash64 of arbitrary strings.
// Sharding avoids a global lock and improves write performance.
type StringCache struct {
	shards []shard
	mask   uint64
}

type shard struct {
	mu sync.RWMutex
	m  map[uint64]Entry
}

// NewCache creates a new cache with N shards.
// Use a power of two (e.g. 16, 32, 64) for best performance.
func NewCache(numShards int) *StringCache {
	if numShards <= 0 {
		numShards = 16
	}
	// Round up to next power of 2
	n := 1
	for n < numShards {
		n <<= 1
	}
	c := &StringCache{
		shards: make([]shard, n),
		mask:   uint64(n - 1),
	}
	for i := range c.shards {
		c.shards[i].m = make(map[uint64]Entry)
	}
	return c
}

func (c *StringCache) shardFor(h uint64) *shard {
	return &c.shards[h&c.mask]
}

// Set stores or updates an entry keyed by DN.
func (c *StringCache) Set(dn string, e *Entry) {
	h := GetHash(dn)
	s := c.shardFor(h)
	s.mu.Lock()
	s.m[h] = *e
	s.mu.Unlock()
}

// Get retrieves an entry by DN. Returns (Entry, true) if found.
func (c *StringCache) Get(dn string) (Entry, bool) {
	h := GetHash(dn)
	s := c.shardFor(h)
	s.mu.RLock()
	e, ok := s.m[h]
	s.mu.RUnlock()
	return e, ok
}

// Delete removes an entry by DN if present.
func (c *StringCache) Delete(dn string) {
	h := GetHash(dn)
	s := c.shardFor(h)
	s.mu.Lock()
	delete(s.m, h)
	s.mu.Unlock()
}

// Size returns the approximate number of entries.
func (c *StringCache) Size() int {
	total := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		total += len(s.m)
		s.mu.RUnlock()
	}
	return total
}

// SimpleCache is a simple thread-safe cache for domain name to SID mappings.
type SimpleCache struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewSimpleCache creates a new cache.
func NewSimpleCache() *SimpleCache {
	return &SimpleCache{
		m: make(map[string]string),
	}
}

// Set stores or updates a domain SID mapping.
func (c *SimpleCache) Set(domainName string, sid string) {
	c.mu.Lock()
	c.m[strings.ToUpper(domainName)] = sid
	c.mu.Unlock()
}

// Get retrieves a SID by domain name. Returns (sid, true) if found.
func (c *SimpleCache) Get(domainName string) (string, bool) {
	c.mu.RLock()
	sid, ok := c.m[strings.ToUpper(domainName)]
	c.mu.RUnlock()
	return sid, ok
}

// GPOCacheEntry stores GPO attributes needed for local group processing
type GPOCacheEntry struct {
	GPCFileSysPath string
	Flags          string
}

// GPOCache maintains GPO entries indexed by DN
type GPOCache struct {
	mu sync.RWMutex
	m  map[string]*GPOCacheEntry // Maps DN (lowercase) to GPO entry
}

// NewGPOCache creates a new GPO cache
func NewGPOCache() *GPOCache {
	return &GPOCache{
		m: make(map[string]*GPOCacheEntry),
	}
}

// Set stores a GPO entry by its DN (case-insensitive)
func (c *GPOCache) Set(dn string, entry *GPOCacheEntry) {
	c.mu.Lock()
	c.m[strings.ToLower(dn)] = entry
	c.mu.Unlock()
}

// Get retrieves a GPO entry by DN (case-insensitive)
func (c *GPOCache) Get(dn string) (*GPOCacheEntry, bool) {
	c.mu.RLock()
	entry, ok := c.m[strings.ToLower(dn)]
	c.mu.RUnlock()
	return entry, ok
}
