package bodyprocessors

import (
	"io"
	"strings"

	"github.com/crowdsecurity/coraza/v3/experimental/plugins"
	"github.com/crowdsecurity/coraza/v3/experimental/plugins/plugintypes"
)

type rawBodyProcessor struct {
}

type setterInterface interface {
	Set(string)
}

func (*rawBodyProcessor) ProcessRequest(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, reader); err != nil {
		return err
	}

	v.RequestBody().(setterInterface).Set(buf.String())
	return nil
}

func (*rawBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

var (
	_ plugintypes.BodyProcessor = &rawBodyProcessor{}
)

func init() {
	plugins.RegisterBodyProcessor("raw", func() plugintypes.BodyProcessor {
		return &rawBodyProcessor{}
	})
}
