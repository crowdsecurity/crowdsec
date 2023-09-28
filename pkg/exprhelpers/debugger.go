package exprhelpers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	log "github.com/sirupsen/logrus"
)

type ExprRuntimeDebug struct {
	Logger  *log.Entry
	Lines   []string
	Outputs []OpOutput
}

// we use this struct to store the output of the expr runtime
type OpOutput struct {
	Snippet string

	Func        bool //true if it's a function call
	FuncName    string
	Args        []string
	FuncResults []string
	//
	Comparison bool //true if it's a comparison
	Left       string
	Right      string
	//
	JumpIf  bool //true if it's conditional jump
	IfTrue  bool
	IfFalse bool
	//
	Condition bool //true if it's a condition

	//used for comparisons, conditional jumps and conditions
	StrConditionResult string
	ConditionResult    *bool //should always be present for conditions

	//
	Finalized bool //used when a node is finalized, we already fetched result from next OP
}

func (o *OpOutput) String() string {
	ret := ""
	if o.Snippet != "" {
		ret = fmt.Sprintf("[%s] ", o.Snippet)
	}
	if o.Func {
		return ret + fmt.Sprintf("%s(%s) = %s", o.FuncName, strings.Join(o.Args, ", "), strings.Join(o.FuncResults, ", "))

	}
	if o.Comparison {
		return ret + fmt.Sprintf("%s == %s -> %s", o.Left, o.Right, o.StrConditionResult)
	}
	if o.JumpIf {
		if o.IfTrue {
			if o.ConditionResult != nil {
				if *o.ConditionResult {
					return ret + "OR[KO]"
				} else {
					return ret + "OR[OK]"
				}
			} else {
				return ret + "OR(?)"
			}
		}
		if o.IfFalse {
			if o.ConditionResult != nil {
				if *o.ConditionResult {
					return ret + "AND[OK]"
				} else {
					return ret + "AND[KO]"
				}
			} else {
				return ret + "AND(?)"
			}
		}
	}
	return ""
}

func (erp ExprRuntimeDebug) ipDebug(ip int, vm *vm.VM, program *vm.Program, parts []string, outputs []OpOutput) ([]OpOutput, error) {

	IdxOut := len(outputs)
	prevIdxOut := 0

	//when there is a function call or comparison, we need to wait for the next instruction to get the result and "finalize" the previous one
	if IdxOut > 0 {
		prevIdxOut = IdxOut - 1
		if outputs[prevIdxOut].Func && !outputs[prevIdxOut].Finalized {
			erp.Logger.Tracef("previous op was func call, setting result of %d to %v", prevIdxOut, vm.Stack())
			for _, val := range vm.Stack() {
				outputs[prevIdxOut].FuncResults = append(outputs[prevIdxOut].FuncResults, fmt.Sprintf("%v", val))
				outputs[prevIdxOut].Finalized = true
			}
		} else if outputs[prevIdxOut].Comparison && !outputs[prevIdxOut].Finalized {
			stack := vm.Stack()
			erp.Logger.Tracef("previous op was comparison, setting result of %d to %v", prevIdxOut, vm.Stack())
			outputs[prevIdxOut].StrConditionResult = fmt.Sprintf("%+v", stack)
			switch stack[0].(type) {
			case bool:
				outputs[prevIdxOut].ConditionResult = new(bool)
				*outputs[prevIdxOut].ConditionResult = stack[0].(bool)
			}
			outputs[prevIdxOut].Finalized = true
		}
	}

	erp.Logger.Tracef("%s %+v (%+v)", parts[1], vm.Stack(), parts)

	switch parts[1] {
	case "OpTrue": //generated when possible ? (1 == 1)
		out := OpOutput{
			Condition:          true,
			ConditionResult:    new(bool),
			StrConditionResult: "true",
		}
		snip, ok := program.Source.Snippet(ip)
		if ok {
			out.Snippet = snip
		}
		*out.ConditionResult = true
		outputs = append(outputs, out)
	case "OpFalse": //generated when possible ? (1 != 1)
		out := OpOutput{
			Condition:          true,
			ConditionResult:    new(bool),
			StrConditionResult: "false",
		}
		snip, ok := program.Source.Snippet(ip)
		if ok {
			out.Snippet = snip
		}
		*out.ConditionResult = false
		outputs = append(outputs, out)
	case "OpJumpIfTrue": //OR
		stack := vm.Stack()
		out := OpOutput{
			JumpIf:             true,
			IfTrue:             true,
			StrConditionResult: fmt.Sprintf("%v", stack[0]),
		}
		snip, ok := program.Source.Snippet(ip)
		if ok {
			out.Snippet = snip
		}
		switch stack[0].(type) {
		case bool:
			out.ConditionResult = new(bool)
			*out.ConditionResult = stack[0].(bool)
		}
		outputs = append(outputs, out)
	case "OpJumpIfFalse": //AND
		stack := vm.Stack()
		out := OpOutput{
			JumpIf:             true,
			IfFalse:            true,
			StrConditionResult: fmt.Sprintf("%v", stack[0]),
		}
		snip, ok := program.Source.Snippet(ip)
		if ok {
			out.Snippet = snip
		}
		switch stack[0].(type) {
		case bool:
			out.ConditionResult = new(bool)
			*out.ConditionResult = stack[0].(bool)
		}
		outputs = append(outputs, out)
	case "OpCall1", "OpCall2", "OpCall3", "OpCallN", "OpCallFast", "OpCallTyped": //Op for function calls
		out := OpOutput{
			Func:     true,
			FuncName: parts[3],
		}
		snip, ok := program.Source.Snippet(ip)
		if ok {
			out.Snippet = snip
		}
		for _, val := range vm.Stack() {
			out.Args = append(out.Args, fmt.Sprintf("%v", val))
		}
		outputs = append(outputs, out)
	case "OpEqualString", "OpEqual", "OpEqualInt": //comparisons
		stack := vm.Stack()
		out := OpOutput{
			Comparison: true,
			Left:       fmt.Sprintf("%v", stack[0]),
			Right:      fmt.Sprintf("%v", stack[1]),
		}
		snip, ok := program.Source.Snippet(ip)
		if ok {
			out.Snippet = snip
		}
		outputs = append(outputs, out)
	}
	return outputs, nil
}

func (erp ExprRuntimeDebug) ipSeek(ip int) []string {
	//Snippet + index ?
	for i := 0; i < len(erp.Lines); i++ {
		parts := strings.Split(erp.Lines[i], "\t")
		if parts[0] == strconv.Itoa(ip) {
			return parts
		}
	}
	return nil
}

func Run(program *vm.Program, env interface{}, logger *log.Entry, debug bool) (any, error) {
	if debug {
		dbgInfo, ret, err := RunWithDebug(program, env, logger)
		DisplayExprDebug(program, dbgInfo, logger)
		return ret, err
	} else {
		return expr.Run(program, env)

	}
}

func DisplayExprDebug(program *vm.Program, outputs []OpOutput, logger *log.Entry) {
	logger.Debugf("dbg: %s", program.Source.Content())
	for _, output := range outputs {
		logger.Debugf("%s", output.String())
	}
}

// TBD: Based on the level of the logger (ie. trace vs debug) we could decide to add more low level instructions (pop, push, etc.)
func RunWithDebug(program *vm.Program, env interface{}, logger *log.Entry) ([]OpOutput, any, error) {

	var outputs []OpOutput = []OpOutput{}
	var buf strings.Builder
	var erp ExprRuntimeDebug = ExprRuntimeDebug{
		Logger: logger,
	}
	var debugErr chan error = make(chan error)

	vm := vm.Debug()
	done := false
	program.Opcodes(&buf)
	lines := strings.Split(buf.String(), "\n")
	erp.Lines = lines

	go func() {
		var err error
		erp.Logger.Tracef("[START] ip 0")
		ops := erp.ipSeek(0)
		if ops == nil {
			debugErr <- fmt.Errorf("failed getting ops for ip 0")
			return
		}
		if outputs, err = erp.ipDebug(0, vm, program, ops, outputs); err != nil {
			debugErr <- fmt.Errorf("error while debugging at ip 0")
		}
		vm.Step()
		for ip := range vm.Position() {
			erp.Logger.Tracef("[STEP] ip %d", ip)
			ops := erp.ipSeek(ip)
			if ops == nil { //we reached the end of the program, we shouldn't throw an error
				erp.Logger.Tracef("[DONE] ip %d", ip)
				debugErr <- nil
				return
			}
			if outputs, err = erp.ipDebug(ip, vm, program, ops, outputs); err != nil {
				debugErr <- fmt.Errorf("error while debugging at ip %d", ip)
				return
			}
			if !done {
				erp.Logger.Tracef("[STEP]")
				vm.Step()
			} else {
				debugErr <- nil
				return
			}
		}
	}()
	ret, err := vm.Run(program, env)
	done = true
	if err != nil {
		return nil, nil, err
	}
	err = <-debugErr
	if err != nil {
		log.Warningf("error while debugging expr: %s", err)
	}
	//the overall result of expression is the result of last op ?
	lastOutIdx := len(outputs)
	if lastOutIdx > 0 {
		lastOutIdx = lastOutIdx - 1
	}
	switch ret.(type) {
	case bool:
		outputs[lastOutIdx].StrConditionResult = fmt.Sprintf("%v", ret)
		outputs[lastOutIdx].ConditionResult = new(bool)
		*outputs[lastOutIdx].ConditionResult = ret.(bool)
		outputs[lastOutIdx].Finalized = true
	default:
		outputs[lastOutIdx].StrConditionResult = fmt.Sprintf("%v", ret)
		outputs[lastOutIdx].Finalized = true

	}
	return outputs, ret, nil
}
