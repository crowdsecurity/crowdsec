// ColoredCobra allows you to colorize Cobra's text output,
// making it look better using simple settings to customize
// individual parts of console output.
//
// Usage example:
//
// 1. Insert in cmd/root.go file of your project :
//
//    import cc "github.com/ivanpirog/coloredcobra"
//
//
// 2. Put the following code to the beginning of the Execute() function:
//
//    cc.Init(&cc.Config{
//        RootCmd:    rootCmd,
//        Headings:   cc.Bold + cc.Underline,
//        Commands:   cc.Yellow + cc.Bold,
//        ExecName:   cc.Bold,
//        Flags:      cc.Bold,
//    })
//
//
// 3. Build & execute your code.
//
//
// Copyright © 2022 Ivan Pirog <ivan.pirog@gmail.com>.
// Released under the MIT license.
// Project home: https://github.com/ivanpirog/coloredcobra
//
package coloredcobra

import (
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// Config is a settings structure which sets styles for individual parts of Cobra text output.
//
// Note that RootCmd is required.
//
// Example:
//
//     c := &cc.Config{
//        RootCmd:       rootCmd,
//        Headings:      cc.HiWhite + cc.Bold + cc.Underline,
//        Commands:      cc.Yellow + cc.Bold,
//        CmdShortDescr: cc.Cyan,
//        ExecName:      cc.Bold,
//        Flags:         cc.Bold,
//        Aliases:       cc.Bold,
//        Example:       cc.Italic,
//     }
type Config struct {
	RootCmd         *cobra.Command
	Headings        uint8
	Commands        uint8
	CmdShortDescr   uint8
	ExecName        uint8
	Flags           uint8
	FlagsDataType   uint8
	FlagsDescr      uint8
	Aliases         uint8
	Example         uint8
	NoExtraNewlines bool
	NoBottomNewline bool
}

// Constants for colors and B, I, U
const (
	None      = 0
	Black     = 1
	Red       = 2
	Green     = 3
	Yellow    = 4
	Blue      = 5
	Magenta   = 6
	Cyan      = 7
	White     = 8
	HiRed     = 9
	HiGreen   = 10
	HiYellow  = 11
	HiBlue    = 12
	HiMagenta = 13
	HiCyan    = 14
	HiWhite   = 15
	Bold      = 16
	Italic    = 32
	Underline = 64
)

// Init patches Cobra's usage template with configuration provided.
func Init(cfg *Config) {

	if cfg.RootCmd == nil {
		panic("coloredcobra: Root command pointer is missing.")
	}

	// Get usage template
	tpl := cfg.RootCmd.UsageTemplate()

	//
	// Add extra line breaks for headings
	//
	if cfg.NoExtraNewlines == false {
		tpl = strings.NewReplacer(
			"Usage:", "\nUsage:\n",
			"Aliases:", "\nAliases:\n",
			"Examples:", "\nExamples:\n",
			"Available Commands:", "\nAvailable Commands:\n",
			"Global Flags:", "\nGlobal Flags:\n",
			"Additional help topics:", "\nAdditional help topics:\n",
			"Use \"", "\nUse \"",
		).Replace(tpl)
		re := regexp.MustCompile(`(?m)^Flags:$`)
		tpl = re.ReplaceAllString(tpl, "\nFlags:\n")
	}

	//
	// Styling headers
	//
	if cfg.Headings != None {
		ch := getColor(cfg.Headings)

		// Add template function to style the headers
		cobra.AddTemplateFunc("HeadingStyle", ch.SprintFunc())

		// Wrap template headers into a new function
		tpl = strings.NewReplacer(
			"Usage:", `{{HeadingStyle "Usage:"}}`,
			"Aliases:", `{{HeadingStyle "Aliases:"}}`,
			"Examples:", `{{HeadingStyle "Examples:"}}`,
			"Available Commands:", `{{HeadingStyle "Available Commands:"}}`,
			"Global Flags:", `{{HeadingStyle "Global Flags:"}}`,
			"Additional help topics:", `{{HeadingStyle "Additional help topics:"}}`,
		).Replace(tpl)

		re := regexp.MustCompile(`(?m)^(\s*)Flags:(\s*)$`)
		tpl = re.ReplaceAllString(tpl, `$1{{HeadingStyle "Flags:"}}$2`)
	}

	//
	// Styling commands
	//
	if cfg.Commands != None {
		cc := getColor(cfg.Commands)

		// Add template function to style commands
		cobra.AddTemplateFunc("CommandStyle", cc.SprintFunc())
		cobra.AddTemplateFunc("sum", func(a, b int) int {
			return a + b
		})

		// Patch usage template
		re := regexp.MustCompile(`(?i){{\s*rpad\s+.Name\s+.NamePadding\s*}}`)
		tpl = re.ReplaceAllLiteralString(tpl, "{{rpad (CommandStyle .Name) (sum .NamePadding 12)}}")

		re = regexp.MustCompile(`(?i){{\s*rpad\s+.CommandPath\s+.CommandPathPadding\s*}}`)
		tpl = re.ReplaceAllLiteralString(tpl, "{{rpad (CommandStyle .CommandPath) (sum .CommandPathPadding 12)}}")
	}

	//
	// Styling a short desription of commands
	//
	if cfg.CmdShortDescr != None {
		csd := getColor(cfg.CmdShortDescr)

		cobra.AddTemplateFunc("CmdShortStyle", csd.SprintFunc())

		re := regexp.MustCompile(`(?ism)({{\s*range\s+.Commands\s*}}.*?){{\s*.Short\s*}}`)
		tpl = re.ReplaceAllString(tpl, `$1{{CmdShortStyle .Short}}`)
	}

	//
	// Styling executable file name
	//
	if cfg.ExecName != None {
		cen := getColor(cfg.ExecName)

		// Add template functions
		cobra.AddTemplateFunc("ExecStyle", cen.SprintFunc())
		cobra.AddTemplateFunc("UseLineStyle", func(s string) string {
			spl := strings.Split(s, " ")
			spl[0] = cen.Sprint(spl[0])
			return strings.Join(spl, " ")
		})

		// Patch usage template
		re := regexp.MustCompile(`(?i){{\s*.CommandPath\s*}}`)
		tpl = re.ReplaceAllLiteralString(tpl, "{{ExecStyle .CommandPath}}")

		re = regexp.MustCompile(`(?i){{\s*.UseLine\s*}}`)
		tpl = re.ReplaceAllLiteralString(tpl, "{{UseLineStyle .UseLine}}")
	}

	//
	// Styling flags
	//
	var cf, cfd, cfdt *color.Color
	if cfg.Flags != None {
		cf = getColor(cfg.Flags)
	}
	if cfg.FlagsDescr != None {
		cfd = getColor(cfg.FlagsDescr)
	}
	if cfg.FlagsDataType != None {
		cfdt = getColor(cfg.FlagsDataType)
	}
	if cf != nil || cfd != nil || cfdt != nil {

		cobra.AddTemplateFunc("FlagStyle", func(s string) string {

			// Flags info section is multi-line.
			// Let's split these lines and iterate them.
			lines := strings.Split(s, "\n")
			for k := range lines {

				// Styling short and full flags (-f, --flag)
				if cf != nil {
					re := regexp.MustCompile(`(--?\S+)`)
					for _, flag := range re.FindAllString(lines[k], 2) {
						lines[k] = strings.Replace(lines[k], flag, cf.Sprint(flag), 1)
					}
				}

				// If no styles for flag data types and description - continue
				if cfd == nil && cfdt == nil {
					continue
				}

				// Split line into two parts: flag data type and description
				// Tip: Use debugger to understand the logic
				re := regexp.MustCompile(`\s{2,}`)
				spl := re.Split(lines[k], -1)
				if len(spl) != 3 {
					continue
				}

				// Styling the flag description
				if cfd != nil {
					lines[k] = strings.Replace(lines[k], spl[2], cfd.Sprint(spl[2]), 1)
				}

				// Styling flag data type
				// Tip: Use debugger to understand the logic
				if cfdt != nil {
					re = regexp.MustCompile(`\s+(\w+)$`) // the last word after spaces is the flag data type
					m := re.FindAllStringSubmatch(spl[1], -1)
					if len(m) == 1 && len(m[0]) == 2 {
						lines[k] = strings.Replace(lines[k], m[0][1], cfdt.Sprint(m[0][1]), 1)
					}
				}

			}
			s = strings.Join(lines, "\n")

			return s

		})

		// Patch usage template
		re := regexp.MustCompile(`(?i)(\.(InheritedFlags|LocalFlags)\.FlagUsages)`)
		tpl = re.ReplaceAllString(tpl, "FlagStyle $1")
	}

	//
	// Styling aliases
	//
	if cfg.Aliases != None {
		ca := getColor(cfg.Aliases)
		cobra.AddTemplateFunc("AliasStyle", ca.SprintFunc())

		re := regexp.MustCompile(`(?i){{\s*.NameAndAliases\s*}}`)
		tpl = re.ReplaceAllLiteralString(tpl, "{{AliasStyle .NameAndAliases}}")
	}

	//
	// Styling the example text
	//
	if cfg.Example != None {
		ce := getColor(cfg.Example)
		cobra.AddTemplateFunc("ExampleStyle", ce.SprintFunc())

		re := regexp.MustCompile(`(?i){{\s*.Example\s*}}`)
		tpl = re.ReplaceAllLiteralString(tpl, "{{ExampleStyle .Example}}")
	}

	// Adding a new line to the end
	if !cfg.NoBottomNewline {
		tpl += "\n"
	}

	// Apply patched template
	cfg.RootCmd.SetUsageTemplate(tpl)
	// Debug line, uncomment when needed
	// fmt.Println(tpl)
}

// getColor decodes color param and returns color.Color object
func getColor(param uint8) (c *color.Color) {

	switch param & 15 {
	case None:
		c = color.New(color.FgWhite)
	case Black:
		c = color.New(color.FgBlack)
	case Red:
		c = color.New(color.FgRed)
	case Green:
		c = color.New(color.FgGreen)
	case Yellow:
		c = color.New(color.FgYellow)
	case Blue:
		c = color.New(color.FgBlue)
	case Magenta:
		c = color.New(color.FgMagenta)
	case Cyan:
		c = color.New(color.FgCyan)
	case White:
		c = color.New(color.FgWhite)
	case HiRed:
		c = color.New(color.FgHiRed)
	case HiGreen:
		c = color.New(color.FgHiGreen)
	case HiYellow:
		c = color.New(color.FgHiYellow)
	case HiBlue:
		c = color.New(color.FgHiBlue)
	case HiMagenta:
		c = color.New(color.FgHiMagenta)
	case HiCyan:
		c = color.New(color.FgHiCyan)
	case HiWhite:
		c = color.New(color.FgHiWhite)
	}

	if param&Bold == Bold {
		c.Add(color.Bold)
	}
	if param&Italic == Italic {
		c.Add(color.Italic)
	}
	if param&Underline == Underline {
		c.Add(color.Underline)
	}

	return
}
