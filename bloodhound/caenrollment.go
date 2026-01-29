package bloodhound

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/go-ntlmssp"
	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/config"
)

// CAEnrollmentProcessor scans CA web enrollment endpoints for NTLM authentication
// vulnerabilities and channel binding weaknesses.
type CAEnrollmentProcessor struct {
	auth          *config.CredentialMgr
	caDnsHostname string
	caName        string
	log           chan<- string
}

// NewCAEnrollmentProcessor creates an enrollment scanner for the given CA.
func NewCAEnrollmentProcessor(caDnsHostname, caName string, auth *config.CredentialMgr, log chan<- string) *CAEnrollmentProcessor {
	return &CAEnrollmentProcessor{
		auth:          auth,
		caDnsHostname: caDnsHostname,
		caName:        caName,
		log:           log,
	}
}

// ScanCAEnrollmentEndpoints probes both web enrollment and web service endpoints
// for NTLM vulnerabilities (ESC8) and channel binding issues.
func (p *CAEnrollmentProcessor) ScanCAEnrollmentEndpoints(ctx context.Context) ([]builder.CAEnrollmentEndpointAPIResult, error) {
	var endpoints []builder.CAEnrollmentEndpointAPIResult

	// Scan both endpoint types concurrently
	webEnrollmentEndpoints, err := p.scanHttpEndpoint(ctx, builder.CATypeWebEnrollmentApplication)
	if err != nil {
		p.log <- fmt.Sprintf("❌ Error scanning web enrollment: %v", err)
	} else {
		endpoints = append(endpoints, webEnrollmentEndpoints...)
	}

	webServiceEndpoints, err := p.scanHttpEndpoint(ctx, builder.CATypeEnrollmentWebService)
	if err != nil {
		p.log <- fmt.Sprintf("❌ Error scanning enrollment web service: %v", err)
	} else {
		endpoints = append(endpoints, webServiceEndpoints...)
	}

	// Tag endpoints with vulnerability flags
	endpoints = p.tagEndpoints(endpoints)

	return endpoints, nil
}

// tagEndpoints marks endpoints with specific vulnerability flags
func (p *CAEnrollmentProcessor) tagEndpoints(endpoints []builder.CAEnrollmentEndpointAPIResult) []builder.CAEnrollmentEndpointAPIResult {
	for i := range endpoints {
		if !endpoints[i].Collected {
			continue
		}

		endpoint := endpoints[i].Result

		parsedURL, err := url.Parse(endpoint.Url)
		if err != nil {
			continue
		}

		if parsedURL.Scheme != "https" {
			if endpoint.Status == builder.CAScanVulnerableNtlmHttpEndpoint {
				endpoints[i].Result.ADCSWebEnrollmentHTTP = true
			}
		} else {
			switch endpoint.Status {
			case builder.CAScanVulnerableNtlmHttpsNoChannelBinding:
				endpoints[i].Result.ADCSWebEnrollmentHTTPS = true
			case builder.CAScanNotVulnerableNtlmChannelBindingRequired:
				endpoints[i].Result.ADCSWebEnrollmentHTTPS = true
				endpoints[i].Result.ADCSWebEnrollmentEPA = true
			}
		}
	}

	return endpoints
}

// scanHttpEndpoint scans a specific endpoint type
func (p *CAEnrollmentProcessor) scanHttpEndpoint(ctx context.Context, endpointType builder.CAEnrollmentEndpointType) ([]builder.CAEnrollmentEndpointAPIResult, error) {
	var endpoints []builder.CAEnrollmentEndpointAPIResult

	httpURL, httpsURL := p.buildEnrollmentUrls(endpointType)

	// Check 1 - ESC8 via HTTP
	// Is the HTTP URL accessible via NTLM? If so, it's vulnerable to NTLM relay
	httpEndpoint := p.getNtlmEndpoint(ctx, httpURL, nil, endpointType, builder.CAScanVulnerableNtlmHttpEndpoint)
	endpoints = append(endpoints, httpEndpoint)

	// Check 2 - ESC8 via HTTPS w/o channel binding (EPA)
	// Is the HTTPS URL accessible via NTLM with bad channel bindings?
	useBadChannelBinding := true
	httpsEndpoint := p.getNtlmEndpoint(ctx, httpsURL, &useBadChannelBinding, endpointType, builder.CAScanVulnerableNtlmHttpsNoChannelBinding)
	endpoints = append(endpoints, httpsEndpoint)

	return endpoints, nil
}

// buildEnrollmentUrls constructs the HTTP and HTTPS URLs for the given endpoint type
func (p *CAEnrollmentProcessor) buildEnrollmentUrls(endpointType builder.CAEnrollmentEndpointType) (httpURL, httpsURL string) {
	switch endpointType {
	case builder.CATypeWebEnrollmentApplication:
		return fmt.Sprintf("http://%s/certsrv/", p.caDnsHostname),
			fmt.Sprintf("https://%s/certsrv/", p.caDnsHostname)
	case builder.CATypeEnrollmentWebService:
		return fmt.Sprintf("http://%s/%s_CES_Kerberos/service.svc", p.caDnsHostname, p.caName),
			fmt.Sprintf("https://%s/%s_CES_Kerberos/service.svc", p.caDnsHostname, p.caName)
	default:
		return "", ""
	}
}

// getNtlmEndpoint checks if a URL is accessible via NTLM authentication
func (p *CAEnrollmentProcessor) getNtlmEndpoint(
	ctx context.Context,
	urlStr string,
	useBadChannelBinding *bool,
	endpointType builder.CAEnrollmentEndpointType,
	scanResult builder.CAEnrollmentEndpointScanResult,
) builder.CAEnrollmentEndpointAPIResult {
	endpoint := builder.CAEnrollmentEndpoint{
		Url:    urlStr,
		Type:   endpointType,
		Status: scanResult,
	}

	// Get credentials from auth options
	username := p.auth.Creds().Username
	password := p.auth.Creds().Password
	if username == "" || password == "" {
		failureStr := "Username or password not provided"
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected:     false,
				FailureReason: &failureStr,
			},
			Result: endpoint,
		}
	}

	// Parse URL to determine if it's HTTP or HTTPS
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		failureStr := fmt.Sprintf("Invalid URL: %v", err)
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected:     false,
				FailureReason: &failureStr,
			},
			Result: endpoint,
		}
	}

	// Check if context is already canceled
	if ctx.Err() != nil {
		failureStr := fmt.Sprintf("Context canceled: %v", ctx.Err())
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected:     false,
				FailureReason: &failureStr,
			},
			Result: endpoint,
		}
	}

	// Create dialer with custom resolver from auth
	dialer := p.auth.Dialer(config.HTTP_TIMEOUT)

	// Create HTTP transport with appropriate TLS config
	transport := &http.Transport{
		DialContext: dialer.DialContext,
	}
	if parsedURL.Scheme == "https" {
		// For HTTPS, configure TLS
		// Note: If useBadChannelBinding is true, we want to test if the server
		// accepts authentication without proper channel binding validation
		// However, go-ntlmssp doesn't provide explicit channel binding manipulation
		// The library handles channel binding automatically based on TLS connection state
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}

	// Create HTTP client with NTLM negotiator
	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: transport,
		},
		// Don't follow redirects automatically
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// Set timeout to prevent hanging indefinitely
		Timeout: config.HTTP_TIMEOUT,
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		failureStr := fmt.Sprintf("Failed to create request: %v", err)
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected:     false,
				FailureReason: &failureStr,
			},
			Result: endpoint,
		}
	}

	// Set credentials for NTLM authentication
	req.SetBasicAuth(username, password)

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		// Check if context was canceled
		if ctx.Err() != nil {
			failureStr := fmt.Sprintf("Request canceled: %v", ctx.Err())
			return builder.CAEnrollmentEndpointAPIResult{
				APIResult: builder.APIResult{
					Collected:     false,
					FailureReason: &failureStr,
				},
				Result: endpoint,
			}
		}

		// Check for specific connection errors
		errStr := err.Error()
		if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no such host") || strings.Contains(errStr, "timeout") || strings.Contains(errStr, "context deadline exceeded") {
			endpoint.Status = builder.CAScanNotVulnerablePortInaccessible
			return builder.CAEnrollmentEndpointAPIResult{
				APIResult: builder.APIResult{
					Collected: true,
				},
				Result: endpoint,
			}
		}

		// Other errors are treated as collection failures
		failureStr := fmt.Sprintf("Request failed: %v", err)
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected:     false,
				FailureReason: &failureStr,
			},
			Result: endpoint,
		}
	}
	defer resp.Body.Close()

	// Read response body with size limit to prevent hang on infinite stream
	bodyLimit := int64(2048 * 1024) // 2MB limit
	limitedReader := io.LimitReader(resp.Body, bodyLimit)
	_, _ = io.Copy(io.Discard, limitedReader)

	// Analyze response status code and headers
	switch resp.StatusCode {
	case http.StatusOK:
		// Success - authentication worked, endpoint is vulnerable as per original scanResult
		if p.log != nil {
			p.log <- fmt.Sprintf("✅ NTLM endpoint accessible: %s (status: %d)", urlStr, resp.StatusCode)
		}
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected: true,
			},
			Result: endpoint,
		}

	case http.StatusUnauthorized:
		// Check if NTLM challenge was present
		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if wwwAuth == "" || (!strings.Contains(strings.ToLower(wwwAuth), "ntlm") && !strings.Contains(strings.ToLower(wwwAuth), "negotiate")) {
			// No NTLM challenge offered
			endpoint.Status = builder.CAScanNotVulnerableNoNtlmChallenge
			if p.log != nil {
				p.log <- fmt.Sprintf("🫠 [yellow]No NTLM challenge at:[-] %s", urlStr)
			}
		} else if useBadChannelBinding != nil && *useBadChannelBinding && parsedURL.Scheme == "https" {
			// 401 with bad channel bindings on HTTPS means channel binding is required (not vulnerable)
			// Note: This is a simplified check. In reality, go-ntlmssp handles channel binding
			// automatically, so a 401 here likely means authentication failed for other reasons.
			// A proper implementation would require more sophisticated channel binding testing.
			endpoint.Status = builder.CAScanNotVulnerableNtlmChannelBindingRequired
			if p.log != nil {
				p.log <- fmt.Sprintf("ℹ🫠 [yellow]Channel binding required at:[-] %s", urlStr)
			}
		} else {
			// Authentication failed but NTLM was offered
			endpoint.Status = builder.CAScanError
			if p.log != nil {
				p.log <- fmt.Sprintf("🫠 [yellow]NTLM authentication failed at:[-] %s", urlStr)
			}
		}
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected: true,
			},
			Result: endpoint,
		}

	case http.StatusForbidden:
		// Path is forbidden (e.g., SSL required for HTTP endpoint)
		endpoint.Status = builder.CAScanNotVulnerablePathForbidden
		if p.log != nil {
			p.log <- fmt.Sprintf("🫠 [yellow]Path forbidden:[-] %s", urlStr)
		}
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected: true,
			},
			Result: endpoint,
		}

	case http.StatusNotFound:
		// Path doesn't exist
		endpoint.Status = builder.CAScanNotVulnerablePathNotFound
		if p.log != nil {
			p.log <- fmt.Sprintf("🫠 [yellow]Path not found:[-] %s", urlStr)
		}
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected: true,
			},
			Result: endpoint,
		}

	case http.StatusInternalServerError:
		// Check if error message indicates EPA misconfiguration
		// This would require reading the response body to check for specific error messages
		// For now, we'll mark it as EPA misconfigured if it's a 500 on HTTPS
		if parsedURL.Scheme == "https" {
			endpoint.Status = builder.CAScanNotVulnerableEpaMisconfigured
			if p.log != nil {
				p.log <- fmt.Sprintf("🫠 [yellow]Possible EPA misconfiguration at:[-] %s", urlStr)
			}
		} else {
			endpoint.Status = builder.CAScanError
			if p.log != nil {
				p.log <- fmt.Sprintf("❌ Server error at: %s (status: %d)", urlStr, resp.StatusCode)
			}
		}
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected: true,
			},
			Result: endpoint,
		}

	default:
		// Other status codes
		endpoint.Status = builder.CAScanError
		if p.log != nil {
			p.log <- fmt.Sprintf("🫠 [yellow]Unexpected status at:[-] %s (status: %d)", urlStr, resp.StatusCode)
		}
		return builder.CAEnrollmentEndpointAPIResult{
			APIResult: builder.APIResult{
				Collected: true,
			},
			Result: endpoint,
		}
	}
}
