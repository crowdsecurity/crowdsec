//go:build tinygo.wasm

package re2

/*
#cgo LDFLAGS: -Linternal/wasm -lcre2 -lre2 -lc++ -lc++abi -lclang_rt.builtins-wasm32
*/
import "C"
