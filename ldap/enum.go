package ldap

type WksDesc struct {
	Name string
	Type string
}

// GetWellKnownSIDsData returns the map of well-known SIDs
func GetWellKnownSIDsData() map[string]WksDesc {
	return map[string]WksDesc{
		"S-1-0":        {"Null Authority", "User"},
		"S-1-0-0":      {"Nobody", "User"},
		"S-1-1":        {"World Authority", "User"},
		"S-1-1-0":      {"Everyone", "Group"},
		"S-1-2":        {"Local Authority", "User"},
		"S-1-2-0":      {"Local", "Group"},
		"S-1-2-1":      {"Console Logon", "Group"},
		"S-1-3":        {"Creator Authority", "User"},
		"S-1-3-0":      {"Creator Owner", "User"},
		"S-1-3-1":      {"Creator Group", "Group"},
		"S-1-3-2":      {"Creator Owner Server", "Computer"},
		"S-1-3-3":      {"Creator Group Server", "Computer"},
		"S-1-3-4":      {"Owner Rights", "Group"},
		"S-1-4":        {"Non-unique Authority", "User"},
		"S-1-5":        {"NT Authority", "User"},
		"S-1-5-1":      {"Dialup", "Group"},
		"S-1-5-2":      {"Network", "Group"},
		"S-1-5-3":      {"Batch", "Group"},
		"S-1-5-4":      {"Interactive", "Group"},
		"S-1-5-6":      {"Service", "Group"},
		"S-1-5-7":      {"Anonymous", "Group"},
		"S-1-5-8":      {"Proxy", "Group"},
		"S-1-5-9":      {"Enterprise Domain Controllers", "Group"},
		"S-1-5-10":     {"Principal Self", "User"},
		"S-1-5-11":     {"Authenticated Users", "Group"},
		"S-1-5-12":     {"Restricted Code", "Group"},
		"S-1-5-13":     {"Terminal Server Users", "Group"},
		"S-1-5-14":     {"Remote Interactive Logon", "Group"},
		"S-1-5-15":     {"This Organization", "Group"},
		"S-1-5-17":     {"IUSR", "User"},
		"S-1-5-18":     {"Local System", "User"},
		"S-1-5-19":     {"NT Authority", "User"},
		"S-1-5-20":     {"Network Service", "User"},
		"S-1-5-80-0":   {"All Services ", "Group"},
		"S-1-5-32-544": {"Administrators", "Group"},
		"S-1-5-32-545": {"Users", "Group"},
		"S-1-5-32-546": {"Guests", "Group"},
		"S-1-5-32-547": {"Power Users", "Group"},
		"S-1-5-32-548": {"Account Operators", "Group"},
		"S-1-5-32-549": {"Server Operators", "Group"},
		"S-1-5-32-550": {"Print Operators", "Group"},
		"S-1-5-32-551": {"Backup Operators", "Group"},
		"S-1-5-32-552": {"Replicators", "Group"},
		"S-1-5-32-554": {"Pre-Windows 2000 Compatible Access", "Group"},
		"S-1-5-32-555": {"Remote Desktop Users", "Group"},
		"S-1-5-32-556": {"Network Configuration Operators", "Group"},
		"S-1-5-32-557": {"Incoming Forest Trust Builders", "Group"},
		"S-1-5-32-558": {"Performance Monitor Users", "Group"},
		"S-1-5-32-559": {"Performance Log Users", "Group"},
		"S-1-5-32-560": {"Windows Authorization Access Group", "Group"},
		"S-1-5-32-561": {"Terminal Server License Servers", "Group"},
		"S-1-5-32-562": {"Distributed COM Users", "Group"},
		"S-1-5-32-568": {"IIS_IUSRS", "Group"},
		"S-1-5-32-569": {"Cryptographic Operators", "Group"},
		"S-1-5-32-573": {"Event Log Readers", "Group"},
		"S-1-5-32-574": {"Certificate Service DCOM Access", "Group"},
		"S-1-5-32-575": {"RDS Remote Access Servers", "Group"},
		"S-1-5-32-576": {"RDS Endpoint Servers", "Group"},
		"S-1-5-32-577": {"RDS Management Servers", "Group"},
		"S-1-5-32-578": {"Hyper-V Administrators", "Group"},
		"S-1-5-32-579": {"Access Control Assistance Operators", "Group"},
		"S-1-5-32-580": {"Access Control Assistance Operators", "Group"},
		"S-1-5-32-582": {"Storage Replica Administrators", "Group"},
	}
}

var WELLKNOWN_SIDS = GetWellKnownSIDsData()

var FUNCTIONAL_LEVELS = map[string]string{
	"0": "2000 Mixed/Native",
	"1": "2003 Interim",
	"2": "2003",
	"3": "2008",
	"4": "2008 R2",
	"5": "2012",
	"6": "2012 R2",
	"7": "2016",
}
