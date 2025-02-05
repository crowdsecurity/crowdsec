package cwhub

import (
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

// ItemState is used to keep the local state (i.e. at runtime) of an item.
// This data is not stored in the index, but is displayed with "cscli ... inspect".
type ItemState struct {
	LocalPath            string `json:"local_path,omitempty" yaml:"local_path,omitempty"`
	LocalVersion         string `json:"local_version,omitempty" yaml:"local_version,omitempty"`
	LocalHash            string `json:"local_hash,omitempty" yaml:"local_hash,omitempty"`
	Installed            bool   `json:"installed"`
	local                bool
	Downloaded           bool     `json:"downloaded"`
	UpToDate             bool     `json:"up_to_date"`
	Tainted              bool     `json:"tainted"`
	TaintedBy            []string `json:"tainted_by,omitempty" yaml:"tainted_by,omitempty"`
	BelongsToCollections []string `json:"belongs_to_collections,omitempty" yaml:"belongs_to_collections,omitempty"`
}

// IsLocal returns true if the item has been create by a user (not downloaded from the hub).
func (s *ItemState) IsLocal() bool {
	return s.local
}

// Text returns the status of the item as a string (eg. "enabled,update-available").
func (s *ItemState) Text() string {
	ret := "disabled"

	if s.Installed {
		ret = "enabled"
	}

	if s.IsLocal() {
		ret += ",local"
	}

	if s.Tainted {
		ret += ",tainted"
	} else if !s.UpToDate && !s.IsLocal() {
		ret += ",update-available"
	}

	return ret
}

// Emoji returns the status of the item as an emoji (eg. emoji.Warning).
func (s *ItemState) Emoji() string {
	switch {
	case s.IsLocal():
		return emoji.House
	case !s.Installed:
		return emoji.Prohibited
	case s.Tainted || (!s.UpToDate && !s.IsLocal()):
		return emoji.Warning
	case s.Installed:
		return emoji.CheckMark
	default:
		return emoji.QuestionMark
	}
}
