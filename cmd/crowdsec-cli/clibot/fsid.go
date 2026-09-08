package clibot

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/fsid"
)

func (cli *cliBot) fsid(out io.Writer, raw string) error {
	if raw == "-" {
		in, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("unable to read fsid from stdin: %w", err)
		}

		raw = string(in)
	}

	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("empty fsid")
	}

	parsed, err := fsid.Parse(raw)
	if err != nil {
		return err
	}

	switch cli.cfg().Cscli.Output {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		return enc.Encode(parsed.Fingerprint())
	case "raw":
		return json.NewEncoder(out).Encode(parsed.Fingerprint())
	default:
		parsed.WriteHuman(out)

		return nil
	}
}

func (cli *cliBot) newFsidCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fsid <fsid>",
		Short: "Decode a fingerprint id (FSID) back into a fingerprint",
		Long: `Decode the FSID a challenged browser reports and rebuild the fingerprint object
from it. Only what the FSID encodes can be recovered: bitmasks, screen geometry,
cpu/memory, language and timezone. The remaining signals were folded into
truncated hashes and are shown as such.

Use '-' to read the FSID from stdin. With -o json the reconstructed fingerprint
is printed instead of the summary.`,
		Example: `cscli bot fsid FS1_000000000000000000000_00000h1f2e_1920x1080c8m8b1000h-3ab1_f...
cscli bot fsid -o json FS1_...
echo 'FS1_...' | cscli bot fsid -`,
		Args:              args.ExactArgs(1),
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, a []string) error {
			return cli.fsid(color.Output, a[0])
		},
	}

	return cmd
}
