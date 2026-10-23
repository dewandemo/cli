// Copyright © 2026 Harness Inc.
// SPDX-License-Identifier: Apache-2.0

package projectcopy

import (
	"errors"
	"regexp"
)

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var accountIdentifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func ValidIdentifier(s string) bool { return identifier.MatchString(s) }

type Scope struct {
	Account     string `json:"account"`
	Org         string `json:"org"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

func (s Scope) Validate() error {
	if !accountIdentifier.MatchString(s.Account) || !ValidIdentifier(s.Org) || !ValidIdentifier(s.Source) || !ValidIdentifier(s.Destination) || s.Source == s.Destination {
		return errors.New("project planning requires an account, org, and distinct explicit source/destination project identifiers")
	}
	return nil
}

type Capability string

const (
	Copyable        Capability = "copyable"
	ReferenceOnly   Capability = "reference-only"
	MappingRequired Capability = "mapping-required"
	Blocked         Capability = "blocked"
)

type Item struct {
	Number     int        `json:"number"`
	Type       string     `json:"type"`
	Capability Capability `json:"capability"`
	Reason     string     `json:"reason"`
}

type Report struct {
	Scope             Scope    `json:"scope"`
	Coverage          string   `json:"coverage"`
	Mode              string   `json:"mode"`
	InventoryComplete bool     `json:"inventory_complete"`
	ApplyAvailable    bool     `json:"apply_available"`
	Readiness         string   `json:"readiness"`
	NotInventoried    []string `json:"not_inventoried"`
	Secrets           []Item   `json:"secrets"`
}

func NewReport(s Scope) Report {
	return Report{Scope: s, Coverage: "PARTIAL", Mode: "read-only planning", Readiness: "NOT ASSESSED; destination not checked or created", NotInventoried: []string{"connectors", "pipelines", "all other project resources"}, Secrets: []Item{}}
}
