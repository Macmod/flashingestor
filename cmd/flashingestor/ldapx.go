package main

import (
	attrlistmid "github.com/Macmod/ldapx/middlewares/attrlist"
	basednmid "github.com/Macmod/ldapx/middlewares/basedn"
	filtermid "github.com/Macmod/ldapx/middlewares/filter"
	"github.com/Macmod/ldapx/parser"
)

// applyFilterObfuscation applies ldapx filter middleware chain
func applyFilterObfuscation(filter string, chain string) string {
	if chain == "" || filter == "" {
		return filter
	}

	// Parse string filter to Filter object
	parsedFilter, err := parser.QueryToFilter(filter)
	if err != nil {
		// If parsing fails, return original
		return filter
	}

	// Apply middleware chain
	for _, letter := range chain {
		switch letter {
		case 'C': // Case
			parsedFilter = filtermid.RandCaseFilterObf(0.5)(parsedFilter)
		case 'S': // Spacing
			parsedFilter = filtermid.RandSpacingFilterObf(3)(parsedFilter)
		case 'G': // Garbage
			parsedFilter = filtermid.RandGarbageFilterObf(1, 10, "abcdefghijklmnopqrstuvwxyz")(parsedFilter)
		case 'T': // Replace Tautologies
			parsedFilter = filtermid.ReplaceTautologiesFilterObf()(parsedFilter)
		case 'R': // Reorder Bool
			parsedFilter = filtermid.RandBoolReorderFilterObf()(parsedFilter)
		case 'O': // OID Attribute
			parsedFilter = filtermid.OIDAttributeFilterObf(2, 2, false)(parsedFilter)
		case 'X': // Hex Value
			parsedFilter = filtermid.RandHexValueFilterObf(0.3)(parsedFilter)
		case 't': // Timestamp Garbage
			parsedFilter = filtermid.RandTimestampSuffixFilterObf(5, "abcdefghijklmnopqrstuvwxyz", false)(parsedFilter)
		case 'B': // Add Bool
			parsedFilter = filtermid.RandAddBoolFilterObf(2, 0.5)(parsedFilter)
		case 'D': // Double Negation Bool
			parsedFilter = filtermid.RandDblNegBoolFilterObf(2, 0.5)(parsedFilter)
		case 'M': // DeMorgan Bool
			parsedFilter = filtermid.DeMorganBoolFilterObf()(parsedFilter)
		case 'b': // Exact Bitwise Breakout
			parsedFilter = filtermid.ExactBitwiseBreakoutFilterObf()(parsedFilter)
		case 'd': // Bitwise Decomposition
			parsedFilter = filtermid.BitwiseDecomposeFilterObf(31)(parsedFilter)
		case 'I': // Equality by Inclusion
			parsedFilter = filtermid.EqualityByInclusionFilterObf()(parsedFilter)
		case 'E': // Equality by Exclusion
			parsedFilter = filtermid.EqualityByExclusionFilterObf()(parsedFilter)
		case 'A': // Equality to Approx Match
			parsedFilter = filtermid.EqualityToApproxMatchFilterObf()(parsedFilter)
		case 'x': // Equality to Extensible
			parsedFilter = filtermid.EqualityToExtensibleFilterObf(false)(parsedFilter)
		case 'Z': // Prepend Zeros
			parsedFilter = filtermid.RandPrependZerosFilterObf(3)(parsedFilter)
		case 's': // Substring Split
			parsedFilter = filtermid.RandSubstringSplitFilterObf(0.3)(parsedFilter)
		case 'N': // Names to ANR
			anrSet := []string{
				"name", "displayname", "samaccountname",
				"givenname", "legacyexchangedn", "sn", "proxyaddresses",
				"physicaldeliveryofficename", "msds-additionalsamaccountname",
				"msds-phoneticcompanyname", "msds-phoneticdepartment",
				"msds-phoneticdisplayname", "msds-phoneticfirstname",
				"msds-phoneticlastname",
			}
			parsedFilter = filtermid.ANRAttributeFilterObf(anrSet)(parsedFilter)
		case 'n': // ANR Garbage Substring
			parsedFilter = filtermid.ANRSubstringGarbageFilterObf(3, "abcdefghijklmnopqrstuvwxyz")(parsedFilter)
		}
	}

	// Convert back to string
	result, err := parser.FilterToQuery(parsedFilter)
	if err != nil {
		// If conversion fails, return original
		return filter
	}

	return result
}

// applyAttrListObfuscation applies ldapx attribute list middleware chain
func applyAttrListObfuscation(attrs []string, chain string) []string {
	if chain == "" || len(attrs) == 0 {
		return attrs
	}

	result := attrs
	for _, letter := range chain {
		switch letter {
		case 'C': // Case
			result = attrlistmid.RandCaseAttrListObf(0.5)(result)
		case 'R': // Reorder List
			result = attrlistmid.ReorderListAttrListObf()(result)
		case 'D': // Duplicate
			result = attrlistmid.DuplicateAttrListObf(0.3)(result)
		case 'O': // OID Attribute
			result = attrlistmid.OIDAttributeAttrListObf(2, 2, false)(result)
		case 'G': // Garbage Non-Existing
			result = attrlistmid.GarbageNonExistingAttrListObf(2, 10, "abcdefghijklmnopqrstuvwxyz")(result)
		case 'g': // Garbage Existing
			result = attrlistmid.GarbageExistingAttrListObf(2)(result)
		case 'W': // Replace With Wildcard
			result = attrlistmid.ReplaceWithWildcardAttrListObf()(result)
		case 'w': // Add Wildcard
			result = attrlistmid.AddWildcardAttrListObf()(result)
		case 'p': // Add Plus
			result = attrlistmid.AddPlusAttrListObf()(result)
		case 'E': // Replace With Empty
			result = attrlistmid.ReplaceWithEmptyAttrListObf()(result)
		}
	}
	return result
}

// applyBaseDNObfuscation applies ldapx baseDN middleware chain
func applyBaseDNObfuscation(baseDN string, chain string) string {
	if chain == "" || baseDN == "" {
		return baseDN
	}

	result := baseDN
	for _, letter := range chain {
		switch letter {
		case 'C': // Case
			result = basednmid.RandCaseBaseDNObf(0.5)(result)
		case 'S': // Spacing
			result = basednmid.RandSpacingBaseDNObf(2)(result)
		case 'Q': // Double Quotes
			result = basednmid.DoubleQuotesBaseDNObf()(result)
		case 'O': // OID Attribute
			result = basednmid.OIDAttributeBaseDNObf(2, 2, false)(result)
		case 'X': // Hex Value
			result = basednmid.RandHexValueBaseDNObf(0.3)(result)
		}
	}
	return result
}
