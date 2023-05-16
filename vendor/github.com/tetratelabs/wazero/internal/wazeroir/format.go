package wazeroir

import (
	"bytes"
)

const EntrypointLabel = ".entrypoint"

func Format(ops []Operation) string {
	buf := bytes.NewBuffer(nil)

	_, _ = buf.WriteString(EntrypointLabel + "\n")
	for _, op := range ops {
		str := op.String()
		isLabel := op.Kind() == OperationKindLabel
		if !isLabel {
			const indent = "\t"
			str = indent + str
		}
		_, _ = buf.WriteString(str + "\n")
	}
	return buf.String()
}
