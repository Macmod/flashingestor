package config

import (
	"context"
	"net"
	"sync"
)

// dnsCacheEntry holds cached DNS lookup results
type dnsCacheEntry struct {
	hosts    []string
	addrs    []string
	ips      []net.IP
	ipAddrs  []net.IPAddr
	cname    string
	mx       []*net.MX
	ns       []*net.NS
	port     int
	srvCname string
	srv      []*net.SRV
	txt      []string
}

// dnsCache provides thread-safe caching for DNS lookups
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*dnsCacheEntry
}

// newDNSCache creates a new DNS cache
func newDNSCache() *dnsCache {
	return &dnsCache{
		entries: make(map[string]*dnsCacheEntry),
	}
}

// getHost retrieves cached host lookup results
func (c *dnsCache) getHost(host string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[host]
	if !ok || entry.hosts == nil {
		return nil, false
	}

	return entry.hosts, true
}

// setHost stores host lookup results in cache
func (c *dnsCache) setHost(host string, addrs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[host]
	if !ok {
		entry = &dnsCacheEntry{}
		c.entries[host] = entry
	}

	entry.hosts = addrs
}

// getAddr retrieves cached address lookup results
func (c *dnsCache) getAddr(addr string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[addr]
	if !ok || entry.addrs == nil {
		return nil, false
	}

	return entry.addrs, true
}

// setAddr stores address lookup results in cache
func (c *dnsCache) setAddr(addr string, names []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[addr]
	if !ok {
		entry = &dnsCacheEntry{}
		c.entries[addr] = entry
	}

	entry.addrs = names
}

// getIP retrieves cached IP lookup results
func (c *dnsCache) getIP(key string) ([]net.IP, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || entry.ips == nil {
		return nil, false
	}

	return entry.ips, true
}

// setIP stores IP lookup results in cache
func (c *dnsCache) setIP(key string, ips []net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		entry = &dnsCacheEntry{}
		c.entries[key] = entry
	}

	entry.ips = ips
}

// getIPAddr retrieves cached IPAddr lookup results
func (c *dnsCache) getIPAddr(host string) ([]net.IPAddr, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[host]
	if !ok || entry.ipAddrs == nil {
		return nil, false
	}

	return entry.ipAddrs, true
}

// setIPAddr stores IPAddr lookup results in cache
func (c *dnsCache) setIPAddr(host string, addrs []net.IPAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[host]
	if !ok {
		entry = &dnsCacheEntry{}
		c.entries[host] = entry
	}

	entry.ipAddrs = addrs
}

// getCNAME retrieves cached CNAME lookup results
func (c *dnsCache) getCNAME(host string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[host]
	if !ok || entry.cname == "" {
		return "", false
	}

	return entry.cname, true
}

// setCNAME stores CNAME lookup results in cache
func (c *dnsCache) setCNAME(host string, cname string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[host]
	if !ok {
		entry = &dnsCacheEntry{}
		c.entries[host] = entry
	}

	entry.cname = cname
}

// getMX retrieves cached MX lookup results
func (c *dnsCache) getMX(name string) ([]*net.MX, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[name]
	if !ok || entry.mx == nil {
		return nil, false
	}

	return entry.mx, true
}

// setMX stores MX lookup results in cache
func (c *dnsCache) setMX(name string, mx []*net.MX) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[name]
	if !ok {
		entry = &dnsCacheEntry{}
		c.entries[name] = entry
	}

	entry.mx = mx
}

// getNS retrieves cached NS lookup results
func (c *dnsCache) getNS(name string) ([]*net.NS, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[name]
	if !ok || entry.ns == nil {
		return nil, false
	}

	return entry.ns, true
}

// setNS stores NS lookup results in cache
func (c *dnsCache) setNS(name string, ns []*net.NS) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[name]
	if !ok {
		entry = &dnsCacheEntry{}
		c.entries[name] = entry
	}

	entry.ns = ns
}

// getPort retrieves cached port lookup results
func (c *dnsCache) getPort(key string) (int, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || entry.port == 0 {
		return 0, false
	}

	return entry.port, true
}

// setPort stores port lookup results in cache
func (c *dnsCache) setPort(key string, port int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		entry = &dnsCacheEntry{}
		c.entries[key] = entry
	}

	entry.port = port
}

// getSRV retrieves cached SRV lookup results
func (c *dnsCache) getSRV(key string) (string, []*net.SRV, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || entry.srv == nil {
		return "", nil, false
	}

	return entry.srvCname, entry.srv, true
}

// setSRV stores SRV lookup results in cache
func (c *dnsCache) setSRV(key string, cname string, srv []*net.SRV) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		entry = &dnsCacheEntry{}
		c.entries[key] = entry
	}

	entry.srvCname = cname
	entry.srv = srv
}

// getTXT retrieves cached TXT lookup results
func (c *dnsCache) getTXT(name string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[name]
	if !ok || entry.txt == nil {
		return nil, false
	}

	return entry.txt, true
}

// setTXT stores TXT lookup results in cache
func (c *dnsCache) setTXT(name string, txt []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[name]
	if !ok {
		entry = &dnsCacheEntry{}
		c.entries[name] = entry
	}

	entry.txt = txt
}

// CustomResolver wraps net.Resolver with caching
type CustomResolver struct {
	resolver *net.Resolver
	cache    *dnsCache
}

// LookupHost performs a cached host lookup
func (cr *CustomResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	// Check cache first
	if cached, ok := cr.cache.getHost(host); ok {
		return cached, nil
	}

	// Perform actual lookup
	result, err := cr.resolver.LookupHost(ctx, host)
	if err == nil {
		cr.cache.setHost(host, result)
	}

	return result, err
}

// LookupAddr performs a cached address lookup
func (cr *CustomResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	// Check cache first
	if cached, ok := cr.cache.getAddr(addr); ok {
		return cached, nil
	}

	// Perform actual lookup
	result, err := cr.resolver.LookupAddr(ctx, addr)
	if err == nil {
		cr.cache.setAddr(addr, result)
	}

	return result, err
}

// LookupIP performs a cached IP lookup
func (cr *CustomResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	key := network + ":" + host

	// Check cache first
	if cached, ok := cr.cache.getIP(key); ok {
		return cached, nil
	}

	// Perform actual lookup
	result, err := cr.resolver.LookupIP(ctx, network, host)
	if err == nil {
		cr.cache.setIP(key, result)
	}

	return result, err
}

// LookupIPAddr performs a cached IPAddr lookup
func (cr *CustomResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	// Check cache first
	if cached, ok := cr.cache.getIPAddr(host); ok {
		return cached, nil
	}

	// Perform actual lookup
	result, err := cr.resolver.LookupIPAddr(ctx, host)
	if err == nil {
		cr.cache.setIPAddr(host, result)
	}

	return result, err
}

// LookupCNAME performs a cached CNAME lookup
func (cr *CustomResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	// Check cache first
	if cached, ok := cr.cache.getCNAME(host); ok {
		return cached, nil
	}

	// Perform actual lookup
	result, err := cr.resolver.LookupCNAME(ctx, host)
	if err == nil {
		cr.cache.setCNAME(host, result)
	}

	return result, err
}

// LookupMX performs a cached MX lookup
func (cr *CustomResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	// Check cache first
	if cached, ok := cr.cache.getMX(name); ok {
		return cached, nil
	}

	// Perform actual lookup
	result, err := cr.resolver.LookupMX(ctx, name)
	if err == nil {
		cr.cache.setMX(name, result)
	}

	return result, err
}

// LookupNS performs a cached NS lookup
func (cr *CustomResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	// Check cache first
	if cached, ok := cr.cache.getNS(name); ok {
		return cached, nil
	}

	// Perform actual lookup
	result, err := cr.resolver.LookupNS(ctx, name)
	if err == nil {
		cr.cache.setNS(name, result)
	}

	return result, err
}

// LookupPort performs a cached port lookup
func (cr *CustomResolver) LookupPort(ctx context.Context, network, service string) (int, error) {
	key := network + ":" + service

	// Check cache first
	if cached, ok := cr.cache.getPort(key); ok {
		return cached, nil
	}

	// Perform actual lookup
	result, err := cr.resolver.LookupPort(ctx, network, service)
	if err == nil {
		cr.cache.setPort(key, result)
	}

	return result, err
}

// LookupSRV performs a cached SRV lookup
func (cr *CustomResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	key := service + ":" + proto + ":" + name

	// Check cache first
	if cachedCname, cachedSrv, ok := cr.cache.getSRV(key); ok {
		return cachedCname, cachedSrv, nil
	}

	// Perform actual lookup
	cname, srv, err := cr.resolver.LookupSRV(ctx, service, proto, name)
	if err == nil {
		cr.cache.setSRV(key, cname, srv)
	}

	return cname, srv, err
}

// LookupTXT performs a cached TXT lookup
func (cr *CustomResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	// Check cache first
	if cached, ok := cr.cache.getTXT(name); ok {
		return cached, nil
	}

	// Perform actual lookup
	result, err := cr.resolver.LookupTXT(ctx, name)
	if err == nil {
		cr.cache.setTXT(name, result)
	}

	return result, err
}
