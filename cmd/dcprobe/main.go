package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	probing "github.com/prometheus-community/pro-bing"
	"github.com/spf13/pflag"
)

type DCResult struct {
	Hostname        string
	IPAddress       string
	LDAPLatency     *LatencyStats
	LDAPSLatency    *LatencyStats
	KerberosLatency *LatencyStats
	KPASSWDLatency  *LatencyStats
	GCLatency       *LatencyStats
	GCSSLLatency    *LatencyStats
	SMBLatency      *LatencyStats
	EPMLatency      *LatencyStats
	NetBIOSLatency  *LatencyStats
	RDPLatency      *LatencyStats
	PingLatency     *LatencyStats
	Errors          []string
}

type LatencyStats struct {
	Min    time.Duration
	Max    time.Duration
	Avg    time.Duration
	Jitter time.Duration
}

var (
	domain    string
	dnsServer string
	retries   int
	timeout   time.Duration
	noColors  bool
	tests     string
)

var cyan = color.New(color.FgCyan).SprintFunc()
var blue = color.New(color.FgBlue).SprintFunc()
var yellow = color.New(color.FgYellow).SprintFunc()

func main() {
	parseFlags()
	validateInput()
	printBanner()
	printConfiguration()

	resolver := setupResolver()
	dcs := discoverDCs(resolver)

	enabledTests, skipTests := parseEnabledTests()
	if skipTests {
		return
	}

	runTests(dcs, enabledTests)
}

func parseFlags() {
	pflag.StringVarP(&domain, "domain", "d", "", "Domain name to query for DCs (required)")
	pflag.StringVar(&dnsServer, "dns", "", "Custom DNS server (default: system resolver)")
	pflag.IntVarP(&retries, "retries", "r", 1, "Number of retries for latency checks (for jitter calculation)")
	pflag.DurationVarP(&timeout, "timeout", "t", 3*time.Second, "Timeout for each connection attempt")
	pflag.BoolVarP(&noColors, "no-colors", "N", false, "Disable colored output")
	pflag.StringVar(&tests, "tests", "ldap,ldaps,kerberos,ping", "Comma-separated list of tests to run (ldap,ldaps,kerberos,kpasswd,gc,gcssl,smb,epm,netbios,rdp,ping)")
	pflag.Parse()

	if noColors {
		color.NoColor = true
	}
}

func validateInput() {
	if domain == "" {
		fmt.Println("Error: -domain flag is required")
		pflag.Usage()
		os.Exit(1)
	}
}

func printConfiguration() {
	fmt.Printf("🔍 Finding Domain Controllers for: %s\n", cyan(domain))
	if dnsServer != "" {
		fmt.Printf("📡 Using custom DNS server: %s\n", cyan(dnsServer))
	}
	if retries > 1 {
		fmt.Printf("🔁 Retries: %d (for jitter calculation)\n", retries)
	}
	fmt.Println()
}

func setupResolver() *net.Resolver {
	if dnsServer == "" {
		return &net.Resolver{}
	}

	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, dnsServer)
		},
	}
}

func discoverDCs(resolver *net.Resolver) []struct{ Hostname, IPAddress string } {
	dcs := findDomainControllers(domain, resolver, timeout)
	if len(dcs) == 0 {
		red := color.New(color.FgRed, color.Bold).SprintFunc()
		fmt.Println()
		fmt.Printf("%s\n", red("❌ No domain controllers found!"))
		os.Exit(1)
	}

	green := color.New(color.FgGreen).SprintFunc()
	fmt.Printf("\n✅ %s\n", green(fmt.Sprintf("Found %d unique DC(s) for %s", len(dcs), domain)))
	for _, dc := range dcs {
		fmt.Printf("   %s (%s)\n", dc.Hostname, dc.IPAddress)
	}
	fmt.Println()

	return dcs
}

func parseEnabledTests() (map[string]bool, bool) {
	enabledTests := make(map[string]bool)
	skipTests := tests == "" || strings.ToLower(tests) == "none"

	if tests != "" && !skipTests {
		for _, test := range strings.Split(tests, ",") {
			enabledTests[strings.TrimSpace(strings.ToLower(test))] = true
		}
	}

	return enabledTests, skipTests
}

func runTests(dcs []struct{ Hostname, IPAddress string }, enabledTests map[string]bool) {
	if len(enabledTests) == 0 {
		return
	}

	results := make([]DCResult, len(dcs))
	for i, dc := range dcs {
		results[i] = testDC(dc.Hostname, dc.IPAddress, retries, timeout, enabledTests)
	}

	displayErrors(results)
	displayResults(results, enabledTests)
}

type dcDiscovery struct {
	seenIPs       map[string]bool
	seenHostnames map[string]bool
	hostnameToIPs map[string][]string
	ipToHostname  map[string]string
	resolver      *net.Resolver
	timeout       time.Duration
}

func newDCDiscovery(resolver *net.Resolver, timeout time.Duration) *dcDiscovery {
	return &dcDiscovery{
		seenIPs:       make(map[string]bool),
		seenHostnames: make(map[string]bool),
		hostnameToIPs: make(map[string][]string),
		ipToHostname:  make(map[string]string),
		resolver:      resolver,
		timeout:       timeout,
	}
}

func findDomainControllers(domain string, resolver *net.Resolver, timeout time.Duration) []struct{ Hostname, IPAddress string } {
	discovery := newDCDiscovery(resolver, timeout)

	discovery.querySRVRecords(domain)
	discovery.resolveHostnames()
	discovery.queryARecords(domain)
	discovery.performReverseLookups()

	return discovery.consolidateDCs()
}

func (d *dcDiscovery) querySRVRecords(domain string) {
	fmt.Printf("🔎 %s\n", blue("Querying SRV records"))

	srvRecords := []string{
		"_ldap._tcp." + domain,
		"_gc._tcp." + domain,
		"_kerberos._tcp." + domain,
		"_kpasswd._tcp." + domain,
		"_ldap._tcp.dc._msdcs." + domain,
		"_kerberos._tcp.dc._msdcs." + domain,
		"_ldap._tcp.gc._msdcs." + domain,
		"_ldap._tcp.pdc._msdcs." + domain,
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	for _, srvRecord := range srvRecords {
		d.querySingleSRV(ctx, srvRecord)
	}
}

func (d *dcDiscovery) querySingleSRV(ctx context.Context, srvRecord string) {
	fmt.Printf("   > %s\n", cyan(srvRecord))
	_, addrs, err := d.resolver.LookupSRV(ctx, "", "", srvRecord)

	if err != nil {
		yellow := color.New(color.FgYellow).SprintFunc()
		fmt.Printf("   🫠 %s\n", yellow(fmt.Sprintf("Failed: %v", err)))
		return
	}

	if len(addrs) == 0 {
		fmt.Println("🫠 No SRV records found")
		return
	}

	for _, addr := range addrs {
		hostname := strings.TrimSuffix(addr.Target, ".")
		fmt.Printf("      %s (priority: %d, weight: %d, port: %d)\n", hostname, addr.Priority, addr.Weight, addr.Port)
		d.seenHostnames[hostname] = true
	}
}

func (d *dcDiscovery) resolveHostnames() {
	if len(d.seenHostnames) > 0 {
		fmt.Printf("\n🔎 %s\n", blue("Resolving service hostnames..."))
	} else {
		fmt.Printf("\n🫠 %s\n", yellow("SRV lookups were not successful..."))
	}

	for hostname := range d.seenHostnames {
		d.resolveHostname(hostname)
	}
}

func (d *dcDiscovery) resolveHostname(hostname string) {
	fmt.Printf("   > %s\n", cyan(hostname))

	ipCtx, ipCancel := context.WithTimeout(context.Background(), d.timeout)
	ips, err := d.resolver.LookupIP(ipCtx, "ip", hostname)
	ipCancel()

	if err != nil || len(ips) == 0 {
		yellow := color.New(color.FgYellow).SprintFunc()
		fmt.Printf("   🫠 %s\n", yellow(fmt.Sprintf("Could not resolve %s: %v", hostname, err)))
		return
	}

	for _, ip := range ips {
		d.recordIPForHostname(ip.String(), hostname)
	}
}

func (d *dcDiscovery) recordIPForHostname(ipAddr, hostname string) {
	if !d.seenIPs[ipAddr] {
		fmt.Printf("     %s\n", ipAddr)
		d.seenIPs[ipAddr] = true
	} else {
		fmt.Printf("     %s (duplicate IP)\n", ipAddr)
	}

	d.hostnameToIPs[hostname] = append(d.hostnameToIPs[hostname], ipAddr)
	if _, exists := d.ipToHostname[ipAddr]; !exists {
		d.ipToHostname[ipAddr] = hostname
	}
}

func (d *dcDiscovery) queryARecords(domain string) {
	fmt.Printf("\n🔎 %s\n", blue("Querying A/AAAA records..."))
	fmt.Printf("   > %s\n", cyan(domain))

	aCtx, aCancel := context.WithTimeout(context.Background(), d.timeout)
	ips, err := d.resolver.LookupIP(aCtx, "ip", domain)
	aCancel()

	if err != nil {
		yellow := color.New(color.FgYellow).SprintFunc()
		fmt.Printf("   🫠 %s\n", yellow(fmt.Sprintf("Failed: %v", err)))
		return
	}

	for _, ip := range ips {
		ipAddr := ip.String()
		fmt.Printf("     %s\n", ipAddr)
		d.seenIPs[ipAddr] = true
		if _, exists := d.ipToHostname[ipAddr]; !exists {
			d.ipToHostname[ipAddr] = domain
		}
	}
}

func (d *dcDiscovery) performReverseLookups() {
	ipsNeedingReverse := d.collectIPsNeedingReverse()
	if len(ipsNeedingReverse) == 0 {
		return
	}

	fmt.Printf("\n🔎 %s\n", blue("Performing reverse lookups..."))
	for _, ipAddr := range ipsNeedingReverse {
		d.reverseLookup(ipAddr)
	}
}

func (d *dcDiscovery) collectIPsNeedingReverse() []string {
	var ipsNeedingReverse []string
	for ipAddr := range d.seenIPs {
		if _, hasHostname := d.ipToHostname[ipAddr]; !hasHostname {
			ipsNeedingReverse = append(ipsNeedingReverse, ipAddr)
		}
	}
	return ipsNeedingReverse
}

func (d *dcDiscovery) reverseLookup(ipAddr string) {
	revCtx, revCancel := context.WithTimeout(context.Background(), d.timeout)
	names, err := d.resolver.LookupAddr(revCtx, ipAddr)
	revCancel()

	if err != nil || len(names) == 0 {
		fmt.Printf("   🫠  Could not reverse lookup %s: %v\n", ipAddr, err)
		d.ipToHostname[ipAddr] = "N/A"
		return
	}

	hostname := strings.TrimSuffix(names[0], ".")
	fmt.Printf("   📍 %s ← %s\n", cyan(hostname), ipAddr)
	d.ipToHostname[ipAddr] = hostname
}

func (d *dcDiscovery) consolidateDCs() []struct{ Hostname, IPAddress string } {
	var dcs []struct{ Hostname, IPAddress string }
	for ipAddr := range d.seenIPs {
		hostname := d.ipToHostname[ipAddr]
		dcs = append(dcs, struct{ Hostname, IPAddress string }{
			Hostname:  hostname,
			IPAddress: ipAddr,
		})
	}
	return dcs
}

// Helper function to test a TCP port with retries
func testPort(ipAddr, portName, port string, retries int, timeout time.Duration, result *DCResult) *LatencyStats {
	fmt.Printf("   %s... ", portName)
	latencies := make([]time.Duration, 0, retries)
	for i := 0; i < retries; i++ {
		latency, err := testTCPConnection(ipAddr, port, timeout)
		if err != nil {
			if i == 0 {
				yellow := color.New(color.FgYellow).SprintFunc()
				fmt.Printf("%s\n", yellow(fmt.Sprintf("❌ %v", err)))
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", portName, err))
			}
			break
		}
		latencies = append(latencies, latency)
	}
	if len(latencies) > 0 {
		stats := calculateStats(latencies)
		fmt.Printf("✅ %s\n", formatLatency(stats))
		return stats
	}
	return nil
}

type portTest struct {
	key      string
	label    string
	port     string
	setStats func(*DCResult, *LatencyStats)
}

func getPortTests() []portTest {
	return []portTest{
		{"ldap", "LDAP (389)", "389", func(r *DCResult, s *LatencyStats) { r.LDAPLatency = s }},
		{"ldaps", "LDAPS (636)", "636", func(r *DCResult, s *LatencyStats) { r.LDAPSLatency = s }},
		{"kerberos", "Kerberos (88)", "88", func(r *DCResult, s *LatencyStats) { r.KerberosLatency = s }},
		{"kpasswd", "KPASSWD (464)", "464", func(r *DCResult, s *LatencyStats) { r.KPASSWDLatency = s }},
		{"gc", "GC (3268)", "3268", func(r *DCResult, s *LatencyStats) { r.GCLatency = s }},
		{"gcssl", "GC SSL (3269)", "3269", func(r *DCResult, s *LatencyStats) { r.GCSSLLatency = s }},
		{"smb", "SMB (445)", "445", func(r *DCResult, s *LatencyStats) { r.SMBLatency = s }},
		{"epm", "EPM (135)", "135", func(r *DCResult, s *LatencyStats) { r.EPMLatency = s }},
		{"netbios", "NetBIOS (139)", "139", func(r *DCResult, s *LatencyStats) { r.NetBIOSLatency = s }},
		{"rdp", "RDP (3389)", "3389", func(r *DCResult, s *LatencyStats) { r.RDPLatency = s }},
	}
}

func testDC(hostname, ipAddr string, retries int, timeout time.Duration, enabledTests map[string]bool) DCResult {
	result := DCResult{
		Hostname:  hostname,
		IPAddress: ipAddr,
		Errors:    make([]string, 0),
	}

	fmt.Printf("🧪 %s\n", blue(fmt.Sprintf("Testing %s (%s)...", hostname, ipAddr)))

	testPortsForDC(ipAddr, retries, timeout, enabledTests, &result)
	testPingForDC(ipAddr, retries, timeout, enabledTests, &result)

	return result
}

func testPortsForDC(ipAddr string, retries int, timeout time.Duration, enabledTests map[string]bool, result *DCResult) {
	for _, test := range getPortTests() {
		if enabledTests[test.key] {
			stats := testPort(ipAddr, test.label, test.port, retries, timeout, result)
			test.setStats(result, stats)
		}
	}
}

func testPingForDC(ipAddr string, retries int, timeout time.Duration, enabledTests map[string]bool, result *DCResult) {
	if !enabledTests["ping"] {
		return
	}

	fmt.Printf("   Ping... ")
	pingLatencies := make([]time.Duration, 0, retries)

	for i := 0; i < retries; i++ {
		latency, err := testPing(ipAddr, timeout)
		if err != nil {
			if i == 0 {
				yellow := color.New(color.FgYellow).SprintFunc()
				fmt.Printf("%s\n", yellow(fmt.Sprintf("❌ %v", err)))
				result.Errors = append(result.Errors, fmt.Sprintf("Ping: %v", err))
			}
			break
		}
		pingLatencies = append(pingLatencies, latency)
	}

	if len(pingLatencies) > 0 {
		result.PingLatency = calculateStats(pingLatencies)
		fmt.Printf("✅ %s\n", formatLatency(result.PingLatency))
	}
}

func printBanner() {
	banner := ` ____   ____ ____            _          
|  _ \ / ___|  _ \ _ __ ___ | |__   ___ 
| | | | |   | |_) | '__/ _ \| '_ \ / _ \
| |_| | |___|  __/| | | (_) | |_) |  __/
|____/ \____|_|   |_|  \___/|_.__/ \___|
`
	fmt.Println(cyan(banner))
}

func testTCPConnection(host, port string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	latency := time.Since(start)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return latency, nil
}

func testPing(host string, timeout time.Duration) (time.Duration, error) {
	pinger, err := probing.NewPinger(host)
	if err != nil {
		return 0, err
	}

	pinger.Count = 1
	pinger.Timeout = timeout
	pinger.SetPrivileged(true) // Use unprivileged mode

	err = pinger.Run()
	if err != nil {
		return 0, err
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv == 0 {
		return 0, fmt.Errorf("no response")
	}

	return stats.AvgRtt, nil
}

func calculateStats(latencies []time.Duration) *LatencyStats {
	if len(latencies) == 0 {
		return nil
	}

	stats := &LatencyStats{
		Min: latencies[0],
		Max: latencies[0],
	}

	var sum time.Duration
	for _, l := range latencies {
		sum += l
		if l < stats.Min {
			stats.Min = l
		}
		if l > stats.Max {
			stats.Max = l
		}
	}

	stats.Avg = sum / time.Duration(len(latencies))

	// Calculate jitter (max - min) only if we have multiple samples
	if len(latencies) > 1 {
		stats.Jitter = stats.Max - stats.Min
	}

	return stats
}

func formatLatency(stats *LatencyStats) string {
	if stats == nil {
		return "N/A"
	}

	if stats.Jitter > 0 {
		return fmt.Sprintf("avg=%v, min=%v, max=%v, jitter=%v",
			stats.Avg.Round(time.Microsecond),
			stats.Min.Round(time.Microsecond),
			stats.Max.Round(time.Microsecond),
			stats.Jitter.Round(time.Microsecond))
	}

	return fmt.Sprintf("%v", stats.Avg.Round(time.Microsecond))
}

type testColumn struct {
	key    string
	label  string
	getVal func(DCResult) *LatencyStats
}

func getTestColumns() []testColumn {
	return []testColumn{
		{"ldap", "LDAP (389)", func(r DCResult) *LatencyStats { return r.LDAPLatency }},
		{"ldaps", "LDAPS (636)", func(r DCResult) *LatencyStats { return r.LDAPSLatency }},
		{"kerberos", "Kerberos (88)", func(r DCResult) *LatencyStats { return r.KerberosLatency }},
		{"kpasswd", "KPASSWD (464)", func(r DCResult) *LatencyStats { return r.KPASSWDLatency }},
		{"gc", "GC (3268)", func(r DCResult) *LatencyStats { return r.GCLatency }},
		{"gcssl", "GC SSL (3269)", func(r DCResult) *LatencyStats { return r.GCSSLLatency }},
		{"smb", "SMB (445)", func(r DCResult) *LatencyStats { return r.SMBLatency }},
		{"epm", "EPM (135)", func(r DCResult) *LatencyStats { return r.EPMLatency }},
		{"netbios", "NetBIOS (139)", func(r DCResult) *LatencyStats { return r.NetBIOSLatency }},
		{"rdp", "RDP (3389)", func(r DCResult) *LatencyStats { return r.RDPLatency }},
		{"ping", "Ping", func(r DCResult) *LatencyStats { return r.PingLatency }},
	}
}

func displayResults(results []DCResult, enabledTests map[string]bool) {
	fmt.Println()

	testColumns := getTestColumns()
	headers := buildTableHeaders(testColumns, enabledTests)
	table := setupResultsTable(headers)

	sortResultsByLatency(results)
	minLatencies := calculateMinLatencies(results, testColumns, enabledTests)
	minLatencyWins := populateTable(table, results, testColumns, enabledTests, minLatencies)

	table.Render()
	displayWinners(results, minLatencyWins)
}

func buildTableHeaders(testColumns []testColumn, enabledTests map[string]bool) []string {
	headers := []string{"Hostname", "IP Address"}
	for _, test := range testColumns {
		if enabledTests[test.key] {
			headers = append(headers, test.label)
		}
	}
	return headers
}

func setupResultsTable(headers []string) *tablewriter.Table {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(headers)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("│")
	table.SetColumnSeparator("│")
	table.SetRowSeparator("─")
	table.SetHeaderLine(true)
	table.SetTablePadding(" ")
	return table
}

func sortResultsByLatency(results []DCResult) {
	sort.Slice(results, func(i, j int) bool {
		return getMinLatencyForSort(results[i]) < getMinLatencyForSort(results[j])
	})
}

func getMinLatencyForSort(r DCResult) time.Duration {
	if r.LDAPLatency != nil {
		return r.LDAPLatency.Avg
	}
	if r.LDAPSLatency != nil {
		return r.LDAPSLatency.Avg
	}
	if r.PingLatency != nil {
		return r.PingLatency.Avg
	}
	return time.Duration(1<<63 - 1) // Max duration
}

func calculateMinLatencies(results []DCResult, testColumns []testColumn, enabledTests map[string]bool) map[string]time.Duration {
	minLatencies := make(map[string]time.Duration)

	for _, test := range testColumns {
		if !enabledTests[test.key] {
			continue
		}

		minLatencies[test.key] = -1
		for _, result := range results {
			stats := test.getVal(result)
			if stats != nil {
				if minLatencies[test.key] == -1 || stats.Avg < minLatencies[test.key] {
					minLatencies[test.key] = stats.Avg
				}
			}
		}
	}

	return minLatencies
}

func populateTable(table *tablewriter.Table, results []DCResult, testColumns []testColumn, enabledTests map[string]bool, minLatencies map[string]time.Duration) map[string]int {
	green := color.New(color.FgGreen, color.Bold).SprintFunc()
	minLatencyWins := make(map[string]int)

	for _, result := range results {
		row, wins := buildResultRow(result, testColumns, enabledTests, minLatencies, green)
		minLatencyWins[result.Hostname] = wins
		table.Append(row)
	}

	return minLatencyWins
}

func buildResultRow(result DCResult, testColumns []testColumn, enabledTests map[string]bool, minLatencies map[string]time.Duration, green func(...interface{}) string) ([]string, int) {
	yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
	row := []string{result.Hostname, result.IPAddress}
	wins := 0

	for _, test := range testColumns {
		if !enabledTests[test.key] {
			continue
		}

		value, isWin := formatTestValue(result, test, minLatencies, green, yellow)
		if isWin {
			wins++
		}
		row = append(row, value)
	}

	return row, wins
}

func formatTestValue(result DCResult, test testColumn, minLatencies map[string]time.Duration, green, yellow func(...interface{}) string) (string, bool) {
	stats := test.getVal(result)

	if stats != nil {
		var valueRtt, valueJitter string
		valueRtt = fmt.Sprintf("%v", stats.Avg.Round(time.Microsecond))
		if stats.Jitter > 0 {
			valueJitter = fmt.Sprintf("(±%v)", stats.Jitter.Round(time.Microsecond))
		}

		if stats.Avg == minLatencies[test.key] {
			return green(valueRtt) + "\n" + valueJitter, true
		}

		return valueRtt + "\n" + valueJitter, false
	}

	if hasTestError(result, test.key) {
		return yellow("ERROR"), false
	}

	return "N/A", false
}

func hasTestError(result DCResult, testKey string) bool {
	for _, err := range result.Errors {
		if strings.Contains(strings.ToLower(err), testKey) {
			return true
		}
	}
	return false
}

func displayWinners(results []DCResult, minLatencyWins map[string]int) {
	maxWins := 0
	for _, wins := range minLatencyWins {
		if wins > maxWins {
			maxWins = wins
		}
	}

	if maxWins == 0 {
		return
	}

	green := color.New(color.FgGreen, color.Bold).SprintFunc()
	var winners []string
	for _, result := range results {
		if minLatencyWins[result.Hostname] == maxWins {
			winners = append(winners, fmt.Sprintf("%s (%s)", result.Hostname, result.IPAddress))
		}
	}
	sort.Strings(winners)

	fmt.Println()
	fmt.Printf("✅ %s\n   %s\n", green("Likely lowest-latency DC(s):"), strings.Join(winners, "\n   "))
}

func displayErrors(results []DCResult) {
	hasErrors := false
	for _, result := range results {
		if len(result.Errors) > 0 {
			hasErrors = true
			break
		}
	}

	if !hasErrors {
		return
	}

	yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
	fmt.Printf("\n🫠 %s\n", yellow("Errors encountered:"))
	for _, result := range results {
		if len(result.Errors) > 0 {
			fmt.Printf("\n%s (%s):\n", result.Hostname, result.IPAddress)
			for _, err := range result.Errors {
				fmt.Printf("  • %s\n", err)
			}
		}
	}
}
