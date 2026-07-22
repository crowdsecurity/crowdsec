package parser

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// sshGrokPatterns are realistic SSH log patterns inspired by the sshd-logs.yaml parser.
// Each has unique literal strings that enable fast-reject via the grokky literal pre-check.
var sshGrokPatterns = []string{
	// Node 1: Failed auth
	`Failed %{WORD:method} for %{USERNAME:user} from %{IP:src_ip} port %{NUMBER:port} %{WORD:proto}`,
	// Node 2: Disconnected preauth
	`Disconnected from authenticating user %{USERNAME:user} %{IP:src_ip} port %{NUMBER:port} \[preauth\]`,
	// Node 3: Connection closed preauth
	`Connection closed by authenticating user %{USERNAME:user} %{IP:src_ip} port %{NUMBER:port} \[preauth\]`,
	// Node 4: Invalid user
	`Invalid user %{USERNAME:user} from %{IP:src_ip} port %{NUMBER:port}`,
	// Node 5: Key negotiation failure
	`Unable to negotiate with %{IP:src_ip} port %{NUMBER:port}: no matching key exchange method found.`,
	// Node 6: PAM auth failure
	`pam_unix\(sshd:auth\): authentication failure; logname= uid=%{NUMBER:uid} euid=%{NUMBER:euid} tty=ssh ruser= rhost=%{IP:src_ip}`,
	// Node 7: Auth timeout
	`Timeout before authentication for %{IP:src_ip} port %{NUMBER:port}`,
	// Node 8: Refused connection
	`refused connect from %{DATA:host}\(%{IP:src_ip}\)`,
}

// buildBenchNodes creates a parent node with N child grok leaf nodes.
// The parent is a skeleton node (no grok of its own) that delegates to leaves.
func buildBenchNodes(b *testing.B, pctx *UnixParserCtx, ectx EnricherCtx) Node {
	b.Helper()

	parent := Node{
		NodeConfig: NodeConfig{
			Stage:     "s01-parse",
			Name:      "bench-ssh",
			OnSuccess: "next_stage",
		},
	}

	for _, pattern := range sshGrokPatterns {
		child := NodeConfig{
			Grok: GrokPattern{
				RegexpValue: pattern,
				TargetField: "Line.Raw",
			},
		}
		parent.SubNodes = append(parent.SubNodes, child)
	}

	parent.initRuntimeChildrenFromConfig()

	err := parent.compile(pctx, ectx)
	require.NoError(b, err, "failed to compile bench nodes")

	return parent
}

func makeEvent(raw string) pipeline.Event {
	return pipeline.Event{
		Stage: "s01-parse",
		Line: pipeline.Line{
			Raw:    raw,
			Labels: map[string]string{"type": "syslog"},
		},
		Parsed:      make(map[string]string),
		Enriched:    make(map[string]string),
		Meta:        make(map[string]string),
		Unmarshaled: make(map[string]any),
		Type:        pipeline.LOG,
	}
}

func BenchmarkGrokPipeline(b *testing.B) {
	log.SetLevel(log.ErrorLevel)

	pctx, ectx := prepTests(b)
	parent := buildBenchNodes(b, pctx, ectx)

	// Add the stage to pctx so Parse() processes it
	pctx.Stages = []string{"s01-parse"}
	nodes := []Node{parent}

	benchCases := []struct {
		name  string
		input string
	}{
		{
			name:  "no_match",
			input: "Accepted publickey for admin from 10.0.0.1 port 22 ssh2",
		},
		{
			name:  "first_node",
			input: "Failed password for root from 192.168.1.1 port 22 ssh2",
		},
		{
			name:  "fifth_node",
			input: "Unable to negotiate with 123.57.135.134 port 45626: no matching key exchange method found.",
		},
		{
			name:  "eighth_node",
			input: "refused connect from attacker(192.168.1.1)",
		},
	}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				evt := makeEvent(bc.input)
				_, err := Parse(*pctx, evt, nodes, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
