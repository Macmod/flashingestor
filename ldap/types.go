package ldap

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type LDAPEntry struct {
	DN            string
	Attributes    map[string][]string
	RawAttributes map[string][][]byte
}

func (l *LDAPEntry) Init(e *ldap.Entry) {
	l.DN = e.DN
	l.Attributes = make(map[string][]string, len(e.Attributes))
	l.RawAttributes = make(map[string][][]byte, len(e.Attributes))

	for _, attr := range e.Attributes {
		l.Attributes[strings.ToLower(attr.Name)] = attr.Values
		l.RawAttributes[strings.ToLower(attr.Name)] = attr.ByteValues
	}
}

// Normal
func (l *LDAPEntry) GetAttrVals(attrName string, defValue []string) []string {
	vals, ok := l.Attributes[strings.ToLower(attrName)]
	if ok {
		return vals
	}

	return defValue
}

func (l *LDAPEntry) GetAttrVal(attrName string, defValue string) string {
	vals := l.GetAttrVals(attrName, []string{defValue})

	if len(vals) > 0 {
		return vals[0]
	}

	return defValue
}

// Raw
func (l *LDAPEntry) GetAttrRawVals(attrName string, defValue [][]byte) [][]byte {
	vals, ok := l.RawAttributes[strings.ToLower(attrName)]
	if ok {
		return vals
	}

	return defValue
}

func (l *LDAPEntry) GetAttrRawVal(attrName string, defValue []byte) []byte {
	vals := l.GetAttrRawVals(attrName, [][]byte{defValue})

	if len(vals) > 0 {
		return vals[0]
	}

	return defValue
}

// Useful
func (l *LDAPEntry) HasLAPS() bool {
	return l.GetAttrVal("ms-mcs-admpwdexpirationtime", "0") != "0" || l.GetAttrVal("mslaps-passwordexpirationtime", "0") != "0"
}

func (l *LDAPEntry) GetUAC() int64 {
	uac := int64(0)
	if val := l.GetAttrVal("userAccountControl", ""); val != "" {
		fmt.Sscan(val, &uac)
	}

	return uac
}

func (l *LDAPEntry) IsDC() bool {
	uac := l.GetUAC()
	return uac&0x2000 == 0x2000
}

func (l *LDAPEntry) GetSID() string {
	sidBytes := l.GetAttrRawVal("objectSid", []byte{})
	if len(sidBytes) == 0 {
		return ""
	}

	objectSid := ConvertSID(hex.EncodeToString(sidBytes))
	return objectSid
}

var dcReplaceRegex = regexp.MustCompile(`(?i)DC=`)

func (l *LDAPEntry) GetDomainFromDN() string {
	dn := l.DN

	var idx int

	upperDN := strings.ToUpper(dn)
	if strings.Contains(upperDN, "DELETED OBJECTS") {
		pos := strings.Index(upperDN[3:], "DC=")
		if pos >= 0 {
			idx = pos + 3 // adjust for offset
		} else {
			idx = -1
		}
	} else {
		pos := strings.Index(strings.ToLower(dn), "dc=")
		idx = pos
	}

	if idx < 0 {
		return ""
	}

	temp := dn[idx:]
	temp = dcReplaceRegex.ReplaceAllString(temp, "")
	temp = strings.ReplaceAll(temp, ",", ".")
	temp = strings.ToUpper(temp)

	return temp
}

func (l *LDAPEntry) GetDomainSID() (string, error) {
	sid := l.GetSID()
	if sid == "" {
		return "", fmt.Errorf("objectSid attribute is missing or empty")
	}

	sidParts := strings.Split(sid, "-")
	if len(sidParts) < 4 {
		return "", fmt.Errorf("invalid SID format")
	}

	domainSID := strings.Join(sidParts[:len(sidParts)-1], "-")
	return domainSID, nil
}

func (l *LDAPEntry) GetGUID() string {
	guidBytes := l.GetAttrRawVal("objectGUID", []byte{})
	return strings.ToUpper(BytesToGUID(guidBytes))
}

func (l *LDAPEntry) GetParentDN() string {
	if l.DN == "" {
		return ""
	}

	// If DN starts with DC=, it's a domain root, so no parent
	if strings.HasPrefix(strings.ToUpper(l.DN), "DC=") {
		return ""
	}

	// If it's a single component DN, no parent
	components := strings.Split(l.DN, ",")
	if len(components) <= 1 {
		return ""
	}

	// Otherwise, strip first RDN and join
	parentComponents := components[1:]
	return strings.Join(parentComponents, ",")
}
