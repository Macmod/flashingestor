package config

// FallbackOptions returns default runtime options
func FallbackOptions() *RuntimeOptions {
	opts := &RuntimeOptions{}

	// Ingestion defaults
	opts.Ingestion.RecurseTrusts = true
	opts.Ingestion.RecurseFeasibleOnly = true
	opts.Ingestion.IncludeACLs = true
	opts.Ingestion.SearchForest = true
	opts.Ingestion.LdapsToLdapFallback = true
	opts.Ingestion.PromptMsgpackOverwrite = true

	opts.Ingestion.Queries = []QueryDefinition{
		{
			Name:   "Configuration",
			Filter: "(objectClass=*)",
			Attributes: []string{
				"*",
				"nTSecurityDescriptor",
			},
			PageSize: 1000,
		},
		{
			Name:   "Schema",
			Filter: "(|(name=ms-mc*wd)(name=ms-lap*))",
			Attributes: []string{
				"name", "schemaIDGUID",
			},
			PageSize: 10,
		},
		{
			Name:   "Domains",
			Filter: "(objectClass=domain)",
			Attributes: []string{
				"*",
				"objectClass",
				"nTSecurityDescriptor",
			},
			PageSize: 1000,
		},
		{
			Name:   "Trusts",
			Filter: "(objectClass=trustedDomain)",
			Attributes: []string{
				"flatName", "name", "securityIdentifier",
				"trustAttributes", "trustDirection", "trustType",
			},
			PageSize: 1000,
		},
		{
			Name:   "Containers",
			Filter: "(&(!(objectClass=groupPolicyContainer))(objectClass=container))",
			Attributes: []string{
				"distinguishedName", "name", "objectGUID", "isCriticalSystemObject", "objectClass", "objectCategory",
				"description", "whencreated",
				"nTSecurityDescriptor",
			},
			PageSize: 1000,
		},
		{
			Name:   "OrganizationalUnits",
			Filter: "(objectClass=organizationalUnit)",
			Attributes: []string{
				"distinguishedName", "name", "objectGUID", "gPLink", "gPOptions",
				"objectClass",
				"description", "whencreated",
				"nTSecurityDescriptor",
			},
			PageSize: 1000,
		},
		{
			Name:   "Users",
			Filter: "(|(&(objectCategory=person)(objectClass=user))(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))",
			Attributes: []string{
				"sAMAccountName", "distinguishedName", "sAMAccountType",
				"objectSid", "primaryGroupID", "isDeleted", "objectClass",
				"servicePrincipalName", "userAccountControl", "displayName",
				"lastLogon", "lastLogonTimestamp", "pwdLastSet", "mail", "title", "homeDirectory",
				"description", "userPassword", "adminCount", "msDS-AllowedToDelegateTo", "sIDHistory",
				"whencreated", "unicodepwd", "scriptpath",
				"nTSecurityDescriptor",
				"unixuserpassword",
				"msDS-GroupMSAMembership",
				"msDS-ManagedServiceAccount",
				"msDS-GroupManagedServiceAccount",
			},
			PageSize: 1000,
		},
		{
			Name:   "Computers",
			Filter: "(&(sAMAccountType=805306369)(!(objectClass=msDS-GroupManagedServiceAccount))(!(objectClass=msDS-ManagedServiceAccount)))",
			Attributes: []string{
				"samaccountname", "userAccountControl", "distinguishedname",
				"dNSHostName", "samaccounttype", "objectSid", "primaryGroupID", "objectGUID",
				"isDeleted",
				"servicePrincipalName", "msDS-AllowedToDelegateTo", "sIDHistory", "whencreated",
				"lastLogon", "lastLogonTimestamp", "pwdLastSet", "operatingSystem", "description",
				"operatingSystemServicePack", "operatingSystemVersion",
				"nTSecurityDescriptor",
				"msDS-HostServiceAccount",
				"objectClass",
				"msDS-AllowedToActOnBehalfOfOtherIdentity",
				"ms-mcs-admpwdexpirationtime",
				"mslaps-passwordexpirationtime",
			},
			PageSize: 1000,
		},
		{
			Name:   "Groups",
			Filter: "(objectClass=group)",
			Attributes: []string{
				"distinguishedName", "samaccountname", "samaccounttype", "objectsid", "member",
				"objectClass",
				"adminCount", "description", "whencreated",
				"nTSecurityDescriptor",
			},
			PageSize: 1000,
		},
		{
			Name:   "GroupPolicies",
			Filter: "(objectCategory=groupPolicyContainer)",
			Attributes: []string{
				"distinguishedName", "name", "objectGUID", "gPCFileSysPath", "displayName",
				"objectClass",
				"description", "whencreated",
				"nTSecurityDescriptor",
			},
			PageSize: 1000,
		},
	}

	// Remote collection defaults
	opts.RemoteCollection.Methods = []string{
		"userrights",
		"dcregistry",
		"sessions",
		"regsessions",
		"loggedon",
		"ntlmregistry",
		"caregistry",
		"webclient",
		"localgroups",
	}

	// Conversion defaults
	opts.Conversion.MergeRemote = true
	opts.Conversion.WriterBufsize = 33554432 // 32MB
	opts.Conversion.CompressOutput = true
	opts.Conversion.CleanupAfterCompression = true

	return opts
}
