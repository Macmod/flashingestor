package bloodhound

import (
	"context"
	"sync"
	"time"

	"github.com/Macmod/flashingestor/config"
	"github.com/Macmod/flashingestor/msrpc"
)

// RPCManager manages RPC client creation, reuse, and timing measurement
type RPCManager struct {
	targetHost  string
	auth        *config.CredentialMgr
	methodTimes map[string]time.Duration
	mu          sync.Mutex

	// Cached RPC clients for reuse
	winregClient *msrpc.WinregRPC
	lsatClient   *msrpc.LsatRPC
	samrClient   *msrpc.SamrRPC
	lsadClient   *msrpc.LsadRPC
	wkssvcClient *msrpc.WkssvcRPC
	srvsvcClient *msrpc.SrvsvcRPC
}

// NewRPCManager creates a new RPC manager
func NewRPCManager(targetHost string, auth *config.CredentialMgr) *RPCManager {
	return &RPCManager{
		targetHost:  targetHost,
		auth:        auth,
		methodTimes: make(map[string]time.Duration),
	}
}

// GetMethodTimes returns the collected method timing data
func (rm *RPCManager) GetMethodTimes() map[string]time.Duration {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.methodTimes
}

// GetTargetHost returns the target hostname
func (rm *RPCManager) GetTargetHost() string {
	return rm.targetHost
}

// GetOrCreateWinregRPC gets or creates a WinregRPC client and tracks the creation time
func (rm *RPCManager) GetOrCreateWinregRPC(ctx context.Context) (*msrpc.WinregRPC, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.winregClient != nil {
		return rm.winregClient, nil
	}

	start := time.Now()
	client, err := msrpc.NewWinregRPC(ctx, rm.targetHost, rm.auth)
	rm.methodTimes["_rpc_winreg"] = time.Since(start)
	if err == nil {
		rm.winregClient = client
	}
	return client, err
}

// GetOrCreateLsatRPC gets or creates an LsatRPC client and tracks the creation time
func (rm *RPCManager) GetOrCreateLsatRPC(ctx context.Context) (*msrpc.LsatRPC, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.lsatClient != nil {
		return rm.lsatClient, nil
	}

	start := time.Now()
	client, err := msrpc.NewLsatRPC(ctx, rm.targetHost, rm.auth)
	rm.methodTimes["_rpc_lsat"] = time.Since(start)
	if err == nil {
		rm.lsatClient = client
	}
	return client, err
}

// GetOrCreateSamrRPC gets or creates a SamrRPC client and tracks the creation time
func (rm *RPCManager) GetOrCreateSamrRPC(ctx context.Context) (*msrpc.SamrRPC, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.samrClient != nil {
		return rm.samrClient, nil
	}

	start := time.Now()
	client, err := msrpc.NewSamrRPC(ctx, rm.targetHost, rm.auth)
	rm.methodTimes["_rpc_samr"] = time.Since(start)
	if err == nil {
		rm.samrClient = client
	}
	return client, err
}

// GetOrCreateLsadRPC gets or creates an LsadRPC client and tracks the creation time
func (rm *RPCManager) GetOrCreateLsadRPC(ctx context.Context) (*msrpc.LsadRPC, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.lsadClient != nil {
		return rm.lsadClient, nil
	}

	start := time.Now()
	client, err := msrpc.NewLsadRPC(ctx, rm.targetHost, rm.auth)
	rm.methodTimes["_rpc_lsad"] = time.Since(start)
	if err == nil {
		rm.lsadClient = client
	}
	return client, err
}

// GetOrCreateWkssvcRPC gets or creates a WkssvcRPC client and tracks the creation time
func (rm *RPCManager) GetOrCreateWkssvcRPC(ctx context.Context) (*msrpc.WkssvcRPC, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.wkssvcClient != nil {
		return rm.wkssvcClient, nil
	}

	start := time.Now()
	client, err := msrpc.NewWkssvcRPC(ctx, rm.targetHost, rm.auth)
	rm.methodTimes["_rpc_wkssvc"] = time.Since(start)
	if err == nil {
		rm.wkssvcClient = client
	}
	return client, err
}

// GetOrCreateSrvsvcRPC gets or creates a SrvsvcRPC client and tracks the creation time
func (rm *RPCManager) GetOrCreateSrvsvcRPC(ctx context.Context) (*msrpc.SrvsvcRPC, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.srvsvcClient != nil {
		return rm.srvsvcClient, nil
	}

	start := time.Now()
	client, err := msrpc.NewSrvsvcRPC(ctx, rm.targetHost, rm.auth)
	rm.methodTimes["_rpc_srvsvc"] = time.Since(start)
	if err == nil {
		rm.srvsvcClient = client
	}
	return client, err
}

// Close closes all cached RPC clients
func (rm *RPCManager) Close() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.winregClient != nil {
		rm.winregClient.Close()
		rm.winregClient = nil
	}
	if rm.lsatClient != nil {
		rm.lsatClient.Close()
		rm.lsatClient = nil
	}
	if rm.samrClient != nil {
		rm.samrClient.Close()
		rm.samrClient = nil
	}
	if rm.lsadClient != nil {
		rm.lsadClient.Close()
		rm.lsadClient = nil
	}
	if rm.wkssvcClient != nil {
		rm.wkssvcClient.Close()
		rm.wkssvcClient = nil
	}
	if rm.srvsvcClient != nil {
		rm.srvsvcClient.Close()
		rm.srvsvcClient = nil
	}
}
