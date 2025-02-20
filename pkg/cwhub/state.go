package cwhub

import (
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

// ItemState is used to keep the local state (i.e. at runtime) of an item.
// This data is not stored in the index, but is displayed with "cscli ... inspect".
type ItemState struct {
	// Path to the install link or local file -- keep LocalPath for compatibility
	LocalPath            string `yaml:"local_path,omitempty"`
	LocalVersion         string `yaml:"local_version,omitempty"`
	LocalHash            string `yaml:"local_hash,omitempty"`
	DownloadPath         string
	local                bool
	UpToDate             bool     `yaml:"up_to_date"`
	Tainted              bool     `yaml:"tainted"`
	TaintedBy            []string `yaml:"tainted_by,omitempty"`
	BelongsToCollections []string `yaml:"belongs_to_collections,omitempty"`
}

// IsLocal returns true if the item has been create by a user (not downloaded from the hub).
func (s *ItemState) IsLocal() bool {
	return s.local
}

// Text returns the status of the item as a string (eg. "enabled,update-available").
func (s *ItemState) Text() string {
	ret := "disabled"

	if s.IsInstalled() {
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
	case !s.IsInstalled():
		return emoji.Prohibited
	case s.Tainted || (!s.UpToDate && !s.IsLocal()):
		return emoji.Warning
	case s.IsInstalled():
		return emoji.CheckMark
	default:
		return emoji.QuestionMark
	}
}

func (s *ItemState) IsDownloaded() bool {
	return s.DownloadPath != ""
}

func (s *ItemState) IsInstalled() bool {
	return s.LocalPath != ""
}
