package exprhelpers

import "strings"

//Wrappers for stdlib strings function exposed in expr

func Fields(params ...any) (any, error) {
	return strings.Fields(params[0].(string)), nil
}

func Index(params ...any) (any, error) {
	return strings.Index(params[0].(string), params[1].(string)), nil
}

func IndexAny(params ...any) (any, error) {
	return strings.IndexAny(params[0].(string), params[1].(string)), nil
}

func Join(params ...any) (any, error) {
	return strings.Join(params[0].([]string), params[1].(string)), nil
}

func Split(params ...any) (any, error) {
	return strings.Split(params[0].(string), params[1].(string)), nil
}

func SplitAfter(params ...any) (any, error) {
	return strings.SplitAfter(params[0].(string), params[1].(string)), nil
}

func SplitAfterN(params ...any) (any, error) {
	return strings.SplitAfterN(params[0].(string), params[1].(string), params[2].(int)), nil
}

func SplitN(params ...any) (any, error) {
	return strings.SplitN(params[0].(string), params[1].(string), params[2].(int)), nil
}

func Replace(params ...any) (any, error) {
	return strings.Replace(params[0].(string), params[1].(string), params[2].(string), params[3].(int)), nil
}

func ReplaceAll(params ...any) (any, error) {
	return strings.ReplaceAll(params[0].(string), params[1].(string), params[2].(string)), nil
}

func Trim(params ...any) (any, error) {
	return strings.Trim(params[0].(string), params[1].(string)), nil
}

func TrimLeft(params ...any) (any, error) {
	return strings.TrimLeft(params[0].(string), params[1].(string)), nil
}

func TrimPrefix(params ...any) (any, error) {
	return strings.TrimPrefix(params[0].(string), params[1].(string)), nil
}

func TrimRight(params ...any) (any, error) {
	return strings.TrimRight(params[0].(string), params[1].(string)), nil
}

func TrimSpace(params ...any) (any, error) {
	return strings.TrimSpace(params[0].(string)), nil
}

func TrimSuffix(params ...any) (any, error) {
	return strings.TrimSuffix(params[0].(string), params[1].(string)), nil
}
