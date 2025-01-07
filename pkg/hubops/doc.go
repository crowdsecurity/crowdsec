/*
Package hubops is responsible for managing the local hub (items and data files) for CrowdSec.

The index file itself (.index.json) is still managed by pkg/cwhub, which also provides the Hub
and Item structs.

The hubops package is mostly used by cscli for the "cscli <hubtype> install/remove/upgrade ..." commands.

It adopts a command-based pattern: a Plan contains a sequence of Commands. Both Plan and Command
have separate preparation and execution methods.

  - Command Interface:
    The Command interface defines the contract for all operations that can be
    performed on hub items. Each operation implements the Prepare and Run
    methods, allowing for pre-execution setup and actual execution logic.

  - ActionPlan:
    ActionPlan serves as a container for a sequence of Commands. It manages the
    addition of commands, handles dependencies between them, and orchestrates their
    execution. ActionPlan also provides a mechanism for interactive confirmation and dry-run.

To perform operations on hub items, create an ActionPlan and add the desired
Commands to it. Once all commands are added, execute the ActionPlan to perform
the operations in the correct order, handling dependencies and user confirmations.

Example:

	hub := cwhub.NewHub(...)
	plan := hubops.NewActionPlan(hub)

	downloadCmd := hubops.NewDownloadCommand(item, force)
	if err := plan.AddCommand(downloadCmd); err != nil {
		logrus.Fatalf("Failed to add download command: %v", err)
	}

	enableCmd := hubops.NewEnableCommand(item, force)
	if err := plan.AddCommand(enableCmd); err != nil {
		logrus.Fatalf("Failed to add enable command: %v", err)
	}

	if err := plan.Execute(ctx, confirm, dryRun, verbose); err != nil {
		logrus.Fatalf("Failed to execute action plan: %v", err)
	}
*/
package hubops
