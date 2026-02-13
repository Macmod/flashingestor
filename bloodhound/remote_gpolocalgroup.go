package bloodhound

import (
	"context"
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Macmod/flashingestor/bloodhound/builder"
	"github.com/Macmod/flashingestor/core"
	gildap "github.com/Macmod/flashingestor/ldap"
	"github.com/Macmod/flashingestor/smb"
)

// Regular expressions for parsing GPO files
var (
	keyRegex         = regexp.MustCompile(`(.+?)\s*=(.*)`)
	memberRegex      = regexp.MustCompile(`(?s)\[Group Membership\](.*)(?:\[|$)`)
	memberLeftRegex  = regexp.MustCompile(`(.*(?:S-1-5-32-544|S-1-5-32-555|S-1-5-32-562|S-1-5-32-580)__Members)`)
	memberRightRegex = regexp.MustCompile(`(S-1-5-32-544|S-1-5-32-555|S-1-5-32-562|S-1-5-32-580)`)
	extractRidRegex  = regexp.MustCompile(`S-1-5-32-([0-9]{3})`)
)

// GPO action cache
var (
	gpoActionCache   = make(map[string][]GroupAction)
	gpoActionCacheMu sync.RWMutex
)

func isFileNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "file does not exist")
}

// LocalGroupRids represents the RIDs of built-in local groups
type LocalGroupRids int

const (
	LocalGroupNone               LocalGroupRids = 0
	LocalGroupAdministrators     LocalGroupRids = 544
	LocalGroupRemoteDesktopUsers LocalGroupRids = 555
	LocalGroupDcomUsers          LocalGroupRids = 562
	LocalGroupPSRemote           LocalGroupRids = 580
)

// GroupActionOperation represents the type of operation to perform
type GroupActionOperation int

const (
	GroupActionAdd GroupActionOperation = iota
	GroupActionDelete
	GroupActionDeleteUsers
	GroupActionDeleteGroups
)

// GroupActionTarget represents the target type for a group action
type GroupActionTarget int

const (
	GroupActionTargetRestrictedMemberOf GroupActionTarget = iota
	GroupActionTargetRestrictedMember
	GroupActionTargetLocalGroup
)

// validGroupNames maps group names to their RIDs
var validGroupNames = map[string]LocalGroupRids{
	"administrators":          LocalGroupAdministrators,
	"remote desktop users":    LocalGroupRemoteDesktopUsers,
	"remote management users": LocalGroupPSRemote,
	"distributed com users":   LocalGroupDcomUsers,
}

// GroupAction represents an action from a GPO
type GroupAction struct {
	Action     GroupActionOperation
	Target     GroupActionTarget
	TargetSID  string
	TargetType string // User, Group, Computer, etc.
	TargetRID  LocalGroupRids
}

// XML structure definitions for Groups.xml parsing
type GroupsXML struct {
	XMLName xml.Name   `xml:"Groups"`
	Groups  []GroupXML `xml:"Group"`
}

type GroupXML struct {
	Disabled   string        `xml:"disabled,attr"`
	Properties PropertiesXML `xml:"Properties"`
}

type PropertiesXML struct {
	Action          string     `xml:"action,attr"`
	GroupSID        string     `xml:"groupSid,attr"`
	GroupName       string     `xml:"groupName,attr"`
	DeleteAllUsers  string     `xml:"deleteAllUsers,attr"`
	DeleteAllGroups string     `xml:"deleteAllGroups,attr"`
	Members         MembersXML `xml:"Members"`
}

type MembersXML struct {
	Members []MemberXML `xml:"Member"`
}

type MemberXML struct {
	Action string `xml:"action,attr"`
	Name   string `xml:"name,attr"`
	SID    string `xml:"sid,attr"`
}

// GroupResults stores membership for each group type
type GroupResults struct {
	LocalGroups        []builder.TypedPrincipal
	RestrictedMember   []builder.TypedPrincipal
	RestrictedMemberOf []builder.TypedPrincipal
}

// GPOLocalGroupsCollectionResult represents the GPO changes for a single OU or Domain
type GPOLocalGroupsCollectionResult struct {
	DN                string
	ObjectType        string
	GPOChanges        builder.GPOChanges
	AffectedComputers []builder.TypedPrincipal
}

// Tobuilder.TypedPrincipal converts a GroupAction to a builder.TypedPrincipal
func (ga *GroupAction) GetTargetPrincipal() builder.TypedPrincipal {
	return builder.TypedPrincipal{
		ObjectIdentifier: ga.TargetSID,
		ObjectType:       ga.TargetType,
	}
}

func (rc *RemoteCollector) domainNameToDC(domainName string) (string, error) {
	// Lookup _kerberos SRV record for the domain
	resolver := rc.auth.Resolver()
	_, addrs, _ := resolver.LookupSRV(context.Background(), "kerberos", "tcp", domainName)
	if len(addrs) > 0 {
		target := strings.TrimSuffix(addrs[0].Target, ".")
		return target, nil
	}

	return "", fmt.Errorf("could not resolve DC for domain: %s", domainName)
}

// ReadGPOLocalGroupsForTarget processes GPO links for local group changes using DN and gPLink directly
func (rc *RemoteCollector) ReadGPOLocalGroupsForTarget(targetDn string, gpLink string, smbReader *smb.FileReader) (*builder.GPOChanges, error) {
	ret := &builder.GPOChanges{}

	// Extract domain from DN
	domain := gildap.DistinguishedNameToDomain(targetDn)
	if domain == "" {
		return ret, fmt.Errorf("could not extract domain from DN: %s", targetDn)
	}

	// Parse GPLink property to extract enforced and unenforced links
	gpLinks := splitGPLinkProperty(gpLink)
	enforced := []string{}
	unenforced := []string{}

	for _, link := range gpLinks {
		switch link.Status {
		case "0":
			unenforced = append(unenforced, link.DN)
		case "2":
			enforced = append(enforced, link.DN)
			// Status "1" is disabled, so we skip it
		}
	}

	// Combine links in correct order (unenforced first, then enforced)
	orderedLinks := append(unenforced, enforced...)

	// Track if we encountered any real errors (not just "file not found")
	var firstError error

	// Initialize group results for each RID
	data := map[LocalGroupRids]*GroupResults{
		LocalGroupAdministrators: {
			LocalGroups:        []builder.TypedPrincipal{},
			RestrictedMember:   []builder.TypedPrincipal{},
			RestrictedMemberOf: []builder.TypedPrincipal{},
		},
		LocalGroupRemoteDesktopUsers: {
			LocalGroups:        []builder.TypedPrincipal{},
			RestrictedMember:   []builder.TypedPrincipal{},
			RestrictedMemberOf: []builder.TypedPrincipal{},
		},
		LocalGroupDcomUsers: {
			LocalGroups:        []builder.TypedPrincipal{},
			RestrictedMember:   []builder.TypedPrincipal{},
			RestrictedMemberOf: []builder.TypedPrincipal{},
		},
		LocalGroupPSRemote: {
			LocalGroups:        []builder.TypedPrincipal{},
			RestrictedMember:   []builder.TypedPrincipal{},
			RestrictedMemberOf: []builder.TypedPrincipal{},
		},
	}

	skipped_gpos_for_target := 0
	for _, linkDN := range orderedLinks {
		linkDomain := gildap.DistinguishedNameToDomain(linkDN)
		skipAuth := rc.noCrossDomain && !strings.EqualFold(linkDomain, rc.auth.Creds().Domain)

		// Check cache first
		linkKey := strings.ToLower(linkDN)
		gpoActionCacheMu.RLock()
		actions, cached := gpoActionCache[linkKey]
		gpoActionCacheMu.RUnlock()

		if !cached {
			// Get GPO attributes from cache
			gpoEntry, found := builder.BState().GPOCache.Get(linkDN)
			if !found || gpoEntry == nil {
				rc.logger.Log1("🫠 [yellow][%s[] GPO not found in cache: %s[-]", targetDn, linkDN)
				// GPO not in cache, skip
				gpoActionCacheMu.Lock()
				gpoActionCache[linkKey] = []GroupAction{}
				gpoActionCacheMu.Unlock()
				continue
			}

			if skipAuth {
				rc.logger.Log1("🦘 [yellow][%s[] Skipped GPO '%s' from %s: cross-domain auth disabled[-]", targetDn, gpoEntry.Name, linkDomain)
				skipped_gpos_for_target++
				continue
			}

			rc.logger.Log1("📝 Processing GPO '%s' (GUID=%s, DN=%s)", gpoEntry.Name, gpoEntry.GUID, linkDN)

			// This shouldn't be needed usually, but if we're authenticating with Kerberos,
			// we need to resolve the domain name to a real underlying DC hostname,
			// as host/domain is not a valid SPN for the host/cifs service on a DC.
			// Otherwise we would get KDC_ERR_S_PRINCIPAL_UNKNOWN.
			// Perhaps the "right" approach here is related to DFS referrals, but
			// we shall not overcomplicate the implementation unless needed in the future.
			gpoPath := gpoEntry.GPOPath
			gpoPathServer := strings.SplitN(strings.TrimPrefix(gpoPath, `\\`), `\`, 2)[0]
			realServerName, err := rc.domainNameToDC(gpoPathServer)
			if err == nil {
				gpoPath = strings.Replace(gpoPath, gpoPathServer, realServerName, 1)
			} else {
				rc.logger.Log1("🫠 [yellow][%s[] Could not resolve DC for GPO path server '%s'[-]", targetDn, gpoPathServer)
			}

			// Check flags: if flags is "2" or "3", GPO or computer config is disabled
			if gpoEntry.Flags == "2" || gpoEntry.Flags == "3" {
				rc.logger.Log1("🫠 [yellow][%s[] Ignored GPO '%s' from %s: disabled (flags=%s)[-]", targetDn, gpoEntry.Name, linkDomain, gpoEntry.Flags)
				gpoActionCacheMu.Lock()
				gpoActionCache[linkKey] = []GroupAction{}
				gpoActionCacheMu.Unlock()
				continue
			}

			actions = []GroupAction{}

			gpoDomain := gildap.DistinguishedNameToDomain(linkDN)

			// Process files in order: XML first, then template (template overrides XML)
			xmlActions, err := rc.ProcessGPPGroupsFile(gpoPath, gpoDomain, smbReader)
			if err != nil {
				if firstError == nil {
					firstError = fmt.Errorf("failed to read GPO '%s': %w", linkDN, err)
				}
				rc.logger.Log1("❌ [red]Error processing Groups.xml for GPO '%s': %v[-]", linkDN, err)
			}
			actions = append(actions, xmlActions...)

			templateActions, err := rc.ProcessGPOTemplateFile(gpoPath, gpoDomain, smbReader)
			if err != nil {
				if firstError == nil {
					firstError = fmt.Errorf("failed to read GPO '%s': %w", linkDN, err)
				}
				rc.logger.Log1("❌ [red]Error processing GptTmpl.inf for GPO '%s': %v[-]", linkDN, err)
			}
			actions = append(actions, templateActions...)

			actionDetails := ""
			if len(actions) > 0 {
				actionDetails += fmt.Sprintf(" (%d from Groups.xml / %d from GptTmpl.inf)", len(xmlActions), len(templateActions))
			}
			rc.logger.Log0("✅ [blue][%s[] GPO '%s' (%s at %s): %d actions%s", targetDn, gpoEntry.Name, gpoEntry.GUID, linkDN, len(actions), actionDetails)

			// Cache the actions for this GPO
			gpoActionCacheMu.Lock()
			gpoActionCache[linkKey] = actions
			gpoActionCacheMu.Unlock()
		} else {
			gpoName := "[red]UNKNOWN[-]"
			gpoGUID := "[red]UNKNOWN[-]"

			gpoEntry, found := builder.BState().GPOCache.Get(linkDN)
			if found && gpoEntry != nil {
				gpoName = gpoEntry.Name
				gpoGUID = gpoEntry.GUID
			}
			rc.logger.Log2("📦 [blue][%s[] Using cached actions for GPO '%s' (%s at %s): %d actions[-]", targetDn, gpoName, gpoGUID, linkDN, len(actions))
		}

		// If there are no actions for this GPO, skip it
		if len(actions) == 0 {
			continue
		}

		// Apply actions from this GPO before moving to the next one
		// This is important because later GPOs can override earlier ones
		applyActionsToGroupResults(actions, data)
	}

	if skipped_gpos_for_target > 0 {
		firstError = fmt.Errorf("gpo(s) were skipped for '%s' (%d)", targetDn, skipped_gpos_for_target)
	}

	// Logic: RestrictedMemberOf always applies, RestrictedMember overrides LocalGroups
	for rid, results := range data {
		final := []builder.TypedPrincipal{}
		final = append(final, results.RestrictedMemberOf...)

		if len(results.RestrictedMember) > 0 {
			final = append(final, results.RestrictedMember...)
		} else {
			final = append(final, results.LocalGroups...)
		}

		// Deduplicate
		final = deduplicatePrincipals(final)

		switch rid {
		case LocalGroupAdministrators:
			ret.LocalAdmins = final
		case LocalGroupRemoteDesktopUsers:
			ret.RemoteDesktopUsers = final
		case LocalGroupDcomUsers:
			ret.DcomUsers = final
		case LocalGroupPSRemote:
			ret.PSRemoteUsers = final
		}
	}

	// If we encountered any errors, return the first one
	// but still return partial results
	return ret, firstError
}

// ProcessGPPGroupsFile parses a GPO Groups.xml file for group membership changes
func (rc *RemoteCollector) ProcessGPPGroupsFile(basePath, gpoDomain string, reader *smb.FileReader) ([]GroupAction, error) {
	// Construct UNC path to Groups.xml
	uncPath := basePath + "\\MACHINE\\Preferences\\Groups\\Groups.xml"
	rc.logger.Log2("🔍 Reading GPO Groups file '%s'", uncPath)

	// Read file using pooled reader
	data, err := reader.ReadFile(uncPath)
	if err != nil {
		// Distinguish between "file not found" (expected) and real errors (connectivity/permission)
		if isFileNotFoundError(err) {
			rc.logger.Log2("📁 Groups.xml not found at '%s'", uncPath)
			return []GroupAction{}, nil
		}
		// Real error - propagate it
		rc.logger.Log1("❌ [red]Error reading '%s': %v[-]", uncPath, err)
		return nil, fmt.Errorf("read Groups.xml: %w", err)
	}

	actions, err := processGPPGroupsContent(data, gpoDomain, rc.logger)
	if err == nil && len(actions) > 0 {
		rc.logger.Log2("🤺 GPO Groups file '%s' generated %d actions", uncPath, len(actions))
	}
	return actions, err
}

// ProcessGPOTemplateFile parses a GPO GptTmpl.inf file for group membership changes
// from the "Restricted Groups" security setting
func (rc *RemoteCollector) ProcessGPOTemplateFile(basePath, gpoDomain string, reader *smb.FileReader) ([]GroupAction, error) {
	// Construct UNC path to GptTmpl.inf
	uncPath := basePath + "\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
	rc.logger.Log2("🔍 Reading GPO Template file '%s'", uncPath)

	// Read file using pooled reader
	data, err := reader.ReadFile(uncPath)
	if err != nil {
		// Distinguish between "file not found" (expected) and real errors (connectivity/permission)
		if isFileNotFoundError(err) {
			rc.logger.Log2("📁 GptTmpl.inf not found at '%s'", uncPath)
			return []GroupAction{}, nil
		}

		// Real error - propagate it
		rc.logger.Log1("❌ [red]Error reading '%s': %v[-]", uncPath, err)
		return nil, fmt.Errorf("read GptTmpl.inf: %w", err)
	}

	actions, err := processGPOTemplateFileContent(string(data), gpoDomain, rc.logger)
	if err == nil && len(actions) > 0 {
		rc.logger.Log2("🤺 GPO Template file '%s' generated %d actions", uncPath, len(actions))
	}
	return actions, err
}

// Helpers for GPO files processing

// processGPPGroupsContent processes the XML content from a GPO Groups.xml file
func processGPPGroupsContent(xmlData []byte, gpoDomain string, logger *core.Logger) ([]GroupAction, error) {
	var groups GroupsXML
	if err := xml.Unmarshal(xmlData, &groups); err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	actions := []GroupAction{}

	// Process each Groups node
	for _, group := range groups.Groups {
		// Skip if disabled
		if group.Disabled == "1" {
			continue
		}

		// Process Properties
		props := group.Properties

		// Only process Update actions for built-in groups
		if !(props.Action == "U" || props.Action == "u") {
			continue
		}

		// Determine target group
		targetGroup := LocalGroupNone

		// Try to extract from groupSid first
		if props.GroupSID != "" {
			matches := extractRidRegex.FindStringSubmatch(strings.TrimSpace(props.GroupSID))
			if len(matches) >= 2 {
				if rid, err := strconv.Atoi(matches[1]); err == nil {
					if isValidLocalGroupRid(rid) {
						targetGroup = LocalGroupRids(rid)
					}
				}
			}
		}

		// If not found, try groupName
		if targetGroup == LocalGroupNone && props.GroupName != "" {
			if rid, ok := validGroupNames[strings.ToUpper(strings.TrimSpace(props.GroupName))]; ok {
				targetGroup = rid
			}
		}

		// If we still don't have a valid target, skip this group
		if targetGroup == LocalGroupNone {
			continue
		}

		// Process deleteAllUsers flag
		if props.DeleteAllUsers == "1" {
			actions = append(actions, GroupAction{
				Action:    GroupActionDeleteUsers,
				Target:    GroupActionTargetLocalGroup,
				TargetRID: targetGroup,
			})
		}

		// Process deleteAllGroups flag
		if props.DeleteAllGroups == "1" {
			actions = append(actions, GroupAction{
				Action:    GroupActionDeleteGroups,
				Target:    GroupActionTargetLocalGroup,
				TargetRID: targetGroup,
			})
		}

		// Process Members
		for _, member := range props.Members.Members {
			var memberAction GroupActionOperation
			if strings.EqualFold(member.Action, "ADD") {
				memberAction = GroupActionAdd
			} else {
				memberAction = GroupActionDelete
			}

			// Try to resolve by SID first
			if member.SID != "" && strings.TrimSpace(member.SID) != "" {
				sid := strings.TrimSpace(member.SID)
				principal := builder.ResolveSID(sid, gpoDomain)
				if principal.ObjectIdentifier != "" {
					actions = append(actions, GroupAction{
						Action:     memberAction,
						Target:     GroupActionTargetLocalGroup,
						TargetSID:  principal.ObjectIdentifier,
						TargetType: principal.ObjectType,
						TargetRID:  targetGroup,
					})
					continue
				} else {
					logger.Log1("🫠 [yellow]Failed to resolve member SID %s in Groups.xml: not found in caches[-]", sid)
				}
			}

			// Try to resolve by name
			if member.Name != "" && strings.TrimSpace(member.Name) != "" {
				name := strings.TrimSpace(member.Name)
				principal, found := builder.ResolveAccountName(name, gpoDomain)
				if found {
					actions = append(actions, GroupAction{
						Action:     memberAction,
						Target:     GroupActionTargetLocalGroup,
						TargetSID:  principal.ObjectIdentifier,
						TargetType: principal.ObjectType,
						TargetRID:  targetGroup,
					})
				} else {
					logger.Log1("🫠 [yellow]Failed to resolve member name %s in Groups.xml: not found in caches[-]", name)
				}
			}
		}
	}

	return actions, nil
}

// processGPOTemplateFileContent processes the content of a GptTmpl.inf file
func processGPOTemplateFileContent(content, gpoDomain string, logger *core.Logger) ([]GroupAction, error) {
	actions := []GroupAction{}

	// Remove UTF-16 BOM and null bytes if necessary
	content = decodeUTF16(content)

	// Extract [Group Membership] section
	memberMatch := memberRegex.FindStringSubmatch(content)
	if len(memberMatch) < 2 {
		return actions, nil // No [Group Membership] section found
	}

	memberText := strings.TrimSpace(memberMatch[1])

	// Split into individual lines
	memberLines := strings.Split(
		strings.ReplaceAll(
			strings.ReplaceAll(
				memberText,
				"\r\n", "\n",
			),
			"\r", "\n",
		),
		"\n",
	)

	for _, memberLine := range memberLines {
		// Match key=value pattern
		keyMatch := keyRegex.FindStringSubmatch(memberLine)
		if len(keyMatch) < 3 {
			continue
		}

		key := strings.TrimSpace(keyMatch[1])
		val := strings.TrimSpace(keyMatch[2])

		// Check for RestrictedMember pattern (S-1-5-32-XXX__Members=...)
		leftMatch := memberLeftRegex.FindStringSubmatch(key)
		if len(leftMatch) > 0 {
			// Extract RID from the key
			extracted := extractRidRegex.FindStringSubmatch(leftMatch[0])
			if len(extracted) < 2 {
				continue
			}

			rid, err := strconv.Atoi(extracted[1])
			if err != nil || !isValidLocalGroupRid(rid) {
				continue
			}

			// Parse members (comma-separated, may have * prefix)
			members := strings.Split(val, ",")
			for _, member := range members {
				member = strings.TrimSpace(strings.Trim(member, "*"))
				if member == "" {
					continue
				}

				var principal builder.TypedPrincipal
				var found bool
				if strings.HasPrefix(member, "S-1-") {
					// It's a SID
					principal = builder.ResolveSID(member, gpoDomain)
					found = principal.ObjectIdentifier != ""
				} else {
					// It's an account name
					principal, found = builder.ResolveAccountName(member, gpoDomain)
				}

				if found {
					actions = append(actions, GroupAction{
						Target:     GroupActionTargetRestrictedMember,
						Action:     GroupActionAdd,
						TargetSID:  principal.ObjectIdentifier,
						TargetType: principal.ObjectType,
						TargetRID:  LocalGroupRids(rid),
					})
				} else {
					logger.Log1("🫠 [yellow]Skipping member '%s' in GptTmpl.inf: not found in caches[-]", member)
				}
			}
		}

		// Check for RestrictedMemberOf pattern (ACCOUNT__MemberOf=S-1-5-32-XXX,...)
		rightMatches := memberRightRegex.FindAllString(val, -1)
		if len(rightMatches) > 0 {
			// Check if key contains "MemberOf"
			index := strings.Index(strings.ToUpper(key), "MEMBEROF")
			if index > 0 {
				// Extract account name (everything before __MemberOf)
				account := strings.ToUpper(strings.Trim(key[:index-2], "*"))

				principal, found := builder.ResolveAccountName(account, gpoDomain)
				if found {
					for _, match := range rightMatches {
						extracted := extractRidRegex.FindStringSubmatch(match)
						if len(extracted) < 2 {
							continue
						}

						rid, err := strconv.Atoi(extracted[1])
						if err != nil || !isValidLocalGroupRid(rid) {
							continue
						}

						actions = append(actions, GroupAction{
							Target:     GroupActionTargetRestrictedMemberOf,
							Action:     GroupActionAdd,
							TargetSID:  principal.ObjectIdentifier,
							TargetType: principal.ObjectType,
							TargetRID:  LocalGroupRids(rid),
						})
					}
				} else {
					logger.Log1("🫠 [yellow]Skipping account '%s' in GptTmpl.inf: not found in caches[-]", account)
				}
			}
		}
	}

	return actions, nil
}

// applyActionsToGroupResults applies a set of GroupActions to the group results map
// - RestrictedMember sets REPLACE the entire member list for that RID
// - RestrictedMemberOf sets REPLACE the entire memberOf list for that RID
// - LocalGroup actions are applied sequentially (add/delete operations)
func applyActionsToGroupResults(actions []GroupAction, data map[LocalGroupRids]*GroupResults) {
	if len(actions) == 0 {
		return
	}

	// First, process RestrictedMember actions - these REPLACE the entire set
	restrictedMemberSets := make(map[LocalGroupRids][]builder.TypedPrincipal)
	for _, action := range actions {
		if action.Target == GroupActionTargetRestrictedMember {
			restrictedMemberSets[action.TargetRID] = append(restrictedMemberSets[action.TargetRID], action.GetTargetPrincipal())
		}
	}

	// Replace the RestrictedMember sets
	for rid, members := range restrictedMemberSets {
		if results, ok := data[rid]; ok {
			results.RestrictedMember = members
		}
	}

	// Next, process RestrictedMemberOf actions - these also REPLACE the entire set
	restrictedMemberOfSets := make(map[LocalGroupRids][]builder.TypedPrincipal)
	for _, action := range actions {
		if action.Target == GroupActionTargetRestrictedMemberOf {
			restrictedMemberOfSets[action.TargetRID] = append(restrictedMemberOfSets[action.TargetRID], action.GetTargetPrincipal())
		}
	}

	// Replace the RestrictedMemberOf sets
	for rid, members := range restrictedMemberOfSets {
		if results, ok := data[rid]; ok {
			results.RestrictedMemberOf = members
		}
	}

	// Finally, process LocalGroup actions sequentially
	// Group by RID to maintain order within each group
	localGroupActionsByRid := make(map[LocalGroupRids][]GroupAction)
	for _, action := range actions {
		if action.Target == GroupActionTargetLocalGroup {
			localGroupActionsByRid[action.TargetRID] = append(localGroupActionsByRid[action.TargetRID], action)
		}
	}

	// Apply each action in order
	for rid, actionSet := range localGroupActionsByRid {
		if results, ok := data[rid]; ok {
			for _, action := range actionSet {
				switch action.Action {
				case GroupActionAdd:
					results.LocalGroups = append(results.LocalGroups, action.GetTargetPrincipal())
				case GroupActionDelete:
					results.LocalGroups = removePrincipal(results.LocalGroups, action.TargetSID)
				case GroupActionDeleteUsers:
					results.LocalGroups = removePrincipalsByType(results.LocalGroups, "User")
				case GroupActionDeleteGroups:
					results.LocalGroups = removePrincipalsByType(results.LocalGroups, "Group")
				}
			}
		}
	}
}
