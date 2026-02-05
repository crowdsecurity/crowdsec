//go:build !windows

package setup

// noop for non-Windows builds

type ExprWindows struct{}

func NewExprWindows() (*ExprWindows, error) {
	return &ExprWindows{}, nil
}

func (*ExprWindows) ServiceEnabled(_ string) (bool, error) {
	return false, nil
}
