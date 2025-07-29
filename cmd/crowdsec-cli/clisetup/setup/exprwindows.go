//go:build !windows

package setup

//noop for non-Windows builds
type ExprWindows struct{}

func NewExprWindows() (*ExprWindows, error) {
	return &ExprWindows{}, nil
}

func (e *ExprWindows) ServiceEnabled(serviceName string) (bool, error) {
	return false, nil
}
