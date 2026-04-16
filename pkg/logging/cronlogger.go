package logging

type GoCronLoggerAdapter struct {
	Logger ExtLogger
}

func (a GoCronLoggerAdapter) Debug(msg string, args ...any) {
	a.Logger.Debug(append([]any{msg}, args...)...)
}

func (a GoCronLoggerAdapter) Info(msg string, args ...any) {
	a.Logger.Info(append([]any{msg}, args...)...)
}

func (a GoCronLoggerAdapter) Warn(msg string, args ...any) {
	a.Logger.Warn(append([]any{msg}, args...)...)
}

func (a GoCronLoggerAdapter) Error(msg string, args ...any) {
	a.Logger.Error(append([]any{msg}, args...)...)
}
