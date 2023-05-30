package table

type Style int

const (
	StyleNormal    Style = 0
	StyleBold      Style = 1
	StyleDim       Style = 2
	StyleItalic    Style = 3
	StyleUnderline Style = 4

	StyleBlack   Style = 30
	StyleRed     Style = 31
	StyleGreen   Style = 32
	StyleYellow  Style = 33
	StyleBlue    Style = 34
	StyleMagenta Style = 35
	StyleCyan    Style = 36
	StyleWhite   Style = 37

	StyleBrightBlack   Style = 90
	StyleBrightRed     Style = 91
	StyleBrightGreen   Style = 92
	StyleBrightYellow  Style = 93
	StyleBrightBlue    Style = 94
	StyleBrightMagenta Style = 95
	StyleBrightCyan    Style = 96
	StyleBrightWhite   Style = 97
)
