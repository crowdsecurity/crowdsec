package table

type Dividers struct {
	ALL string
	NES string
	NSW string
	NEW string
	ESW string
	NE  string
	NW  string
	SW  string
	ES  string
	EW  string
	NS  string
}

var NoDividers = Dividers{}
var UnicodeDividers = Dividers{
	ALL: "┼",
	NES: "├",
	NSW: "┤",
	NEW: "┴",
	ESW: "┬",
	NE:  "└",
	NW:  "┘",
	SW:  "┐",
	ES:  "┌",
	EW:  "─",
	NS:  "│",
}
var UnicodeRoundedDividers = Dividers{
	ALL: "┼",
	NES: "├",
	NSW: "┤",
	NEW: "┴",
	ESW: "┬",
	NE:  "╰",
	NW:  "╯",
	SW:  "╮",
	ES:  "╭",
	EW:  "─",
	NS:  "│",
}
var ASCIIDividers = Dividers{
	ALL: "+",
	NES: "+",
	NSW: "+",
	NEW: "+",
	ESW: "+",
	NE:  "+",
	NW:  "+",
	SW:  "+",
	ES:  "+",
	EW:  "-",
	NS:  "|",
}
var StarDividers = Dividers{
	ALL: "*",
	NES: "*",
	NSW: "*",
	NEW: "*",
	ESW: "*",
	NE:  "*",
	NW:  "*",
	SW:  "*",
	ES:  "*",
	EW:  "*",
	NS:  "*",
}
var MarkdownDividers = Dividers{
	ALL: "|",
	NES: "|",
	NSW: "|",
	NE:  "|",
	NW:  "|",
	SW:  "|",
	ES:  "|",
	EW:  "-",
	NS:  "|",
}
