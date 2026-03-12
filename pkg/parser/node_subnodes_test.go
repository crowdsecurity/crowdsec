package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

func mustUnmarshalNode(t *testing.T, raw string) Node {
	t.Helper()

	var n Node
	require.NoError(t, yaml.Unmarshal([]byte(raw), &n))
	return n
}

func mustUnmarshalNodeConfig(t *testing.T, raw string) NodeConfig {
	t.Helper()

	var cfg NodeConfig
	require.NoError(t, yaml.Unmarshal([]byte(raw), &cfg))
	return cfg
}

func assertNames(t *testing.T, nodes []Node, want ...string) {
	t.Helper()

	require.Len(t, nodes, len(want))
	for i, w := range want {
		assert.Equal(t, w, nodes[i].Name, "node[%d].Name", i)
	}
}

func TestNodeUnmarshalYAML_PopulatesConfigNodesAndRuntimeLeaves(t *testing.T) {
	raw := `
name: root
stage: s00-raw
nodes:
  - name: child1
    stage: s01-parse
    filter: "evt.Line.Labels.type == 'a'"
  - name: child2
    stage: s02-enrich
    nodes:
      - name: grandchild
        stage: s03-final
`

	n := mustUnmarshalNode(t, raw)

	// Root config
	assert.Equal(t, "root", n.Name)
	require.Len(t, n.NodeConfig.SubNodes, 2)

	// Runtime mirror
	assertNames(t, n.LeavesNodes, "child1", "child2")
	assert.Equal(t, "evt.Line.Labels.type == 'a'", n.LeavesNodes[0].Filter)

	// Nested: child2 -> grandchild (config + runtime mirror)
	child2 := n.LeavesNodes[1]
	require.Len(t, child2.NodeConfig.SubNodes, 1)
	assertNames(t, child2.LeavesNodes, "grandchild")
}

func TestNodeConfigUnmarshalYAML_PopulatesNodes(t *testing.T) {
	raw := `
name: root
nodes:
  - name: child
`

	cfg := mustUnmarshalNodeConfig(t, raw)

	assert.Equal(t, "root", cfg.Name)
	require.Len(t, cfg.SubNodes, 1)
	assert.Equal(t, "child", cfg.SubNodes[0].Name)
}
