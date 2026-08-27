package models

import "time"

// NodeKind classifies a graph node.
type NodeKind string

const (
	NodeDomain   NodeKind = "domain"
	NodeDC       NodeKind = "domain_controller"
	NodeComputer NodeKind = "computer"
	NodeUser     NodeKind = "user"
	NodeGroup    NodeKind = "group"
	NodeOU       NodeKind = "ou"
	NodeGPO      NodeKind = "gpo"
	NodeService  NodeKind = "service"
	NodeResource NodeKind = "resource"
)

// RelationshipType is the edge vocabulary of the Active Directory graph.
type RelationshipType string

const (
	RelMemberOf      RelationshipType = "member_of"        // principal → group
	RelMember        RelationshipType = "member"           // group → principal
	RelContains      RelationshipType = "contains"         // container → object
	RelTrusts        RelationshipType = "trusts"           // domain → domain
	RelTrustedBy     RelationshipType = "trusted_by"       // domain → domain
	RelHasPrivilege  RelationshipType = "has_privilege"    // principal → resource
	RelHasPermission RelationshipType = "has_permission"   // principal → resource
	RelAppliesTo     RelationshipType = "applies_to"       // gpo → ou/computer
	RelRunsOn        RelationshipType = "runs_on"          // service → computer
	RelJoins         RelationshipType = "member_of_domain" // computer/user → domain
	RelAdminOf       RelationshipType = "is_admin_of"      // principal → computer/domain
)

// Node is one vertex in the relationship graph.
type Node struct {
	ID        string    `json:"id"`
	Kind      NodeKind  `json:"kind"`
	Label     string    `json:"label"`
	Domain    string    `json:"domain,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Edge is one directed relationship between two nodes.
type Edge struct {
	ID          string           `json:"id"`
	From        string           `json:"from"`
	To          string           `json:"to"`
	Type        RelationshipType `json:"type"`
	Source      string           `json:"source,omitempty"` // evidence/collection source
	Confidence  Confidence       `json:"confidence,omitempty"`
	EvidenceIDs []string         `json:"evidence_ids,omitempty"`
	Timestamp   time.Time        `json:"timestamp"`
}
