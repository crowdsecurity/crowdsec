package optimizer

import (
	. "github.com/antonmedv/expr/ast"
)

type inRange struct{}

func (*inRange) Visit(node *Node) {
	switch n := (*node).(type) {
	case *BinaryNode:
		if n.Operator == "in" {
			if rng, ok := n.Right.(*BinaryNode); ok && rng.Operator == ".." {
				if from, ok := rng.Left.(*IntegerNode); ok {
					if to, ok := rng.Right.(*IntegerNode); ok {
						Patch(node, &BinaryNode{
							Operator: "and",
							Left: &BinaryNode{
								Operator: ">=",
								Left:     n.Left,
								Right:    from,
							},
							Right: &BinaryNode{
								Operator: "<=",
								Left:     n.Left,
								Right:    to,
							},
						})
					}
				}
			}
		}
	}
}
