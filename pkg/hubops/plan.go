package hubops

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"

	"github.com/crowdsecurity/go-cs-lib/slicetools"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

// Command represents an operation that can be performed on a CrowdSec hub item.
//
// Each concrete implementation defines a Prepare() method to check for errors and preconditions,
// decide which sub-commands are required (like installing dependencies) and add them to the action plan.
type Command interface {
	// Prepare sets up the command for execution within the given
	// ActionPlan. It may add additional commands to the ActionPlan based
	// on dependencies or prerequisites. Returns a boolean indicating
	// whether the command execution should be skipped (it can be
	// redundant, like installing something that is already installed) and
	// an error if the preparation failed.
	// NOTE: Returning an error will bubble up from the plan.AddCommand() method,
	// but Prepare() might already have modified the plan's command slice.
	Prepare(*ActionPlan) (bool, error)

	// Run executes the command within the provided context and ActionPlan.
	// It performs the actual operation and returns an error if execution fails.
	// NOTE: Returning an error will currently stop the execution of the action plan.
	Run(ctx context.Context, plan *ActionPlan) error

	// OperationType returns a unique string representing the type of operation to perform
	// (e.g., "download", "enable").
	OperationType() string

	// ItemType returns the type of item the operation is performed on
	// (e.g., "collections"). Used in confirmation prompt and dry-run.
	ItemType() string

	// Detail provides further details on the operation,
	// such as the item's name and version.
	Detail() string
}

// UniqueKey generates a unique string key for a Command based on its operation type, item type, and detail.
// Is is used to avoid adding duplicate commands to the action plan.
func UniqueKey(c Command) string {
	return fmt.Sprintf("%s:%s:%s", c.OperationType(), c.ItemType(), c.Detail())
}

// ActionPlan orchestrates the sequence of operations (Commands) to manage CrowdSec hub items.
type ActionPlan struct {
	// hold the list of Commands to be executed as part of the action plan.
	// If a command is skipped (i.e. calling Prepare() returned false), it won't be included in the slice.
	commands []Command

	// Tracks unique commands
	commandsTracker map[string]struct{}

	// A reference to the Hub instance, required for dependency lookup.
	hub *cwhub.Hub

	// Indicates whether a reload of the CrowdSec service is required after executing the action plan.
	ReloadNeeded bool
}

func NewActionPlan(hub *cwhub.Hub) *ActionPlan {
	return &ActionPlan{
		hub:             hub,
		commandsTracker: make(map[string]struct{}),
	}
}

func (p *ActionPlan) AddCommand(c Command) error {
	ok, err := c.Prepare(p)
	if err != nil {
		return err
	}

	if ok {
		key := UniqueKey(c)
		if _, exists := p.commandsTracker[key]; !exists {
			p.commands = append(p.commands, c)
			p.commandsTracker[key] = struct{}{}
		}
	}

	return nil
}

func (p *ActionPlan) Info(msg string) {
	fmt.Println(msg)
}

func (p *ActionPlan) Warning(msg string) {
	fmt.Printf("%s %s\n", color.YellowString("WARN"), msg)
}

// Description returns a string representation of the action plan.
// If verbose is false, the operations are grouped by item type and operation type.
// If verbose is true, they are listed as they appear in the command slice.
func (p *ActionPlan) Description(verbose bool) string {
	if verbose {
		return p.verboseDescription()
	}

	return p.compactDescription()
}

func (p *ActionPlan) verboseDescription() string {
	sb := strings.Builder{}

	// Here we display the commands in the order they will be executed.
	for _, cmd := range p.commands {
		sb.WriteString(colorizeOpType(cmd.OperationType()) + " " + cmd.ItemType() + ":" + cmd.Detail() + "\n")
	}

	return sb.String()
}

// describe the operations of a given type in a compact way.
func describe(opType string, desc map[string]map[string][]string, sb *strings.Builder) {
	if _, ok := desc[opType]; !ok {
		return
	}

	sb.WriteString(colorizeOpType(opType) + "\n")

	// iterate cwhub.ItemTypes in reverse order, so we have collections first
	for _, itemType := range slicetools.Backward(cwhub.ItemTypes) {
		if desc[opType][itemType] == nil {
			continue
		}

		details := desc[opType][itemType]
		// Sorting for user convenience, but it's not the same order the commands will be carried out.
		slices.Sort(details)

		if itemType != "" {
			sb.WriteString(" " + itemType + ": ")
		}

		if len(details) != 0 {
			sb.WriteString(strings.Join(details, ", "))
			sb.WriteString("\n")
		}
	}
}

func (p *ActionPlan) compactDescription() string {
	desc := make(map[string]map[string][]string)

	for _, cmd := range p.commands {
		opType := cmd.OperationType()
		itemType := cmd.ItemType()
		detail := cmd.Detail()

		if _, ok := desc[opType]; !ok {
			desc[opType] = make(map[string][]string)
		}

		desc[opType][itemType] = append(desc[opType][itemType], detail)
	}

	sb := strings.Builder{}

	// Enforce presentation order.

	describe("download", desc, &sb)
	delete(desc, "download")
	describe("enable", desc, &sb)
	delete(desc, "enable")
	describe("disable", desc, &sb)
	delete(desc, "disable")
	describe("remove", desc, &sb)
	delete(desc, "remove")

	for optype := range desc {
		describe(optype, desc, &sb)
	}

	return sb.String()
}

func (p *ActionPlan) Confirm(verbose bool) (bool, error) {
	fmt.Println("The following actions will be performed:\n" + p.Description(verbose))

	var answer bool

	prompt := &survey.Confirm{
		Message: "Do you want to continue?",
		Default: true,
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return prompt.Default, nil
	}
	defer tty.Close()

	// in case of EOF, it's likely stdin has been closed in a script or package manager,
	// we can't do anything but go with the default
	if err := survey.AskOne(prompt, &answer, survey.WithStdio(tty, tty, tty)); err != nil {
		if errors.Is(err, io.EOF) {
			return prompt.Default, nil
		}

		return false, err
	}

	fmt.Println()

	return answer, nil
}

func (p *ActionPlan) Execute(ctx context.Context, interactive bool, dryRun bool, alwaysShowPlan bool, verbosePlan bool) error {
	// interactive: show action plan, ask for confirm
	// dry-run: show action plan, no prompt, no action
	// alwaysShowPlan: print plan even if interactive and dry-run are false
	// verbosePlan: plan summary is displaying each step in order
	if len(p.commands) == 0 {
		fmt.Println("Nothing to do.")
		return nil
	}

	if interactive {
		answer, err := p.Confirm(verbosePlan)
		if err != nil {
			return err
		}

		if !answer {
			fmt.Println("Operation canceled.")
			return nil
		}
	} else {
		if dryRun || alwaysShowPlan {
			fmt.Println("Action plan:\n" + p.Description(verbosePlan))
		}

		if dryRun {
			fmt.Println("Dry run, no action taken.")
			return nil
		}
	}

	for _, c := range p.commands {
		if err := c.Run(ctx, p); err != nil {
			return err
		}
	}

	return nil
}
