package bloodhound

import (
	"strings"

	"github.com/Macmod/flashingestor/bloodhound/builder"
)

// OUTreeNode represents a node in the OU hierarchy tree
type OUTreeNode struct {
	DN        string
	Computers []builder.TypedPrincipal // Computers directly in this OU
	Children  map[string]*OUTreeNode   // Child OUs (keyed by their full DN)
}

// NewOUTreeNode creates a new OU tree node
func NewOUTreeNode(dn string) *OUTreeNode {
	return &OUTreeNode{
		DN:        dn,
		Computers: []builder.TypedPrincipal{},
		Children:  make(map[string]*OUTreeNode),
	}
}

// GetAllComputersInSubtree returns all computers in this OU and all child OUs (iterative)
func (node *OUTreeNode) GetAllComputersInSubtree() []builder.TypedPrincipal {
	result := make([]builder.TypedPrincipal, 0)

	// Use a stack for iterative DFS
	stack := []*OUTreeNode{node}

	for len(stack) > 0 {
		// Pop from stack
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// Add computers from current node
		result = append(result, current.Computers...)

		// Push children onto stack
		for _, child := range current.Children {
			stack = append(stack, child)
		}
	}

	return result
}

// findNodeInTree finds a node with the given DN in the tree using direct path lookup
func findNodeInTree(root *OUTreeNode, targetDN string) (*OUTreeNode, bool) {
	// If target is the root
	if root.DN == targetDN {
		return root, true
	}

	// Parse DN into components (treating all DC= parts as one component)
	// Returns: [targetDN, parentDN, grandparentDN, ..., domainDN]
	// Example: "OU=A,OU=B,DC=X,DC=Y" -> ["OU=A,OU=B,DC=X,DC=Y", "OU=B,DC=X,DC=Y", "DC=X,DC=Y"]
	components := parseDNComponents(targetDN)

	// If only domain component exists, we're already at root
	if len(components) <= 1 {
		return root, true
	}

	// Build path from parent (closest to root) to target
	// Skip the last element (domain = root) and reverse the rest
	// From: [target, parent, grandparent, domain]
	// To:   [grandparent, parent, target]
	path := make([]string, 0, len(components)-1)
	for i := len(components) - 2; i >= 0; i-- {
		path = append(path, components[i])
	}

	// Follow the path using direct map lookups
	currentNode := root
	for _, dn := range path {
		if child, exists := currentNode.Children[dn]; exists {
			currentNode = child
		} else {
			return nil, false
		}
	}

	return currentNode, true
}

// buildOUTreeFromComputers builds a hierarchical tree structure from computer DNs
func buildOUTreeFromComputers(computersByDomain map[string]map[string]string) map[string]*OUTreeNode {
	trees := make(map[string]*OUTreeNode)

	for domain, computers := range computersByDomain {
		// Create root node for domain
		domainDN := strings.ToUpper(domain)
		root := NewOUTreeNode(domainDN)
		trees[domain] = root

		// Build tree by inserting each computer
		for computerDN, sid := range computers {
			// Extract parent DN (everything after first comma)
			commaIdx := strings.Index(computerDN, ",")
			if commaIdx == -1 {
				// Computer directly in domain (no OU)
				root.Computers = append(root.Computers, builder.TypedPrincipal{
					ObjectIdentifier: sid,
					ObjectType:       "Computer",
				})
				continue
			}

			parentDN := computerDN[commaIdx+1:]

			// Find or create the node for this parent DN
			node := findOrCreateNode(root, parentDN)
			node.Computers = append(node.Computers, builder.TypedPrincipal{
				ObjectIdentifier: sid,
				ObjectType:       "Computer",
			})
		}
	}

	return trees
}

// findOrCreateNode finds or creates a node in the tree for the given DN (iterative)
func findOrCreateNode(root *OUTreeNode, targetDN string) *OUTreeNode {
	// Check if we're at the target (domain level)
	if targetDN == root.DN {
		return root
	}

	// Parse DN into components (treating all DC= parts as one component)
	// Returns: [targetDN, parentDN, grandparentDN, ..., domainDN]
	// Example: "OU=A,OU=B,DC=X,DC=Y" -> ["OU=A,OU=B,DC=X,DC=Y", "OU=B,DC=X,DC=Y", "DC=X,DC=Y"]
	components := parseDNComponents(targetDN)

	// If only domain component exists, we're already at root
	if len(components) <= 1 {
		return root
	}

	// Build path from parent (closest to root) to target
	// Skip the last element (domain = root) and reverse the rest
	// From: [target, parent, grandparent, domain]
	// To:   [grandparent, parent, target]
	path := make([]string, 0, len(components)-1)
	for i := len(components) - 2; i >= 0; i-- {
		path = append(path, components[i])
	}

	// Walk down the path, creating nodes as needed
	currentNode := root
	for _, dn := range path {
		if child, exists := currentNode.Children[dn]; exists {
			currentNode = child
		} else {
			newNode := NewOUTreeNode(dn)
			currentNode.Children[dn] = newNode
			currentNode = newNode
		}
	}

	return currentNode
}
