package bodyprocessors

import (
	"io"
	"strconv"
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

	b := buf.String()

	v.RequestBody().(setterInterface).Set(b)
	v.RequestBodyLength().(setterInterface).Set(strconv.Itoa(len(b)))
	return nil
}

func (*rawBodyProcessor) ProcessResponse(reader io.Reader, v plugintypes.TransactionVariables, options plugintypes.BodyProcessorOptions) error {
	return nil
}

var (
	_ plugintypes.BodyProcessor = &rawBodyProcessor{}
)

//nolint:gochecknoinits //Coraza recommends to use init() for registering plugins
func init() {
	plugins.RegisterBodyProcessor("raw", func() plugintypes.BodyProcessor {
		return &rawBodyProcessor{}
	})
}
