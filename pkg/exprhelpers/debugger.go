package exprhelpers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/file"
	"github.com/expr-lang/expr/vm"
	log "github.com/sirupsen/logrus"
)

type ExprRuntimeDebug struct {
	Logger  *log.Entry
	Lines   []string
	Outputs []OpOutput
}

const IndentStep = 4

// we use this struct to store the output of the expr runtime
type OpOutput struct {
	Code string // relevant code part

	CodeDepth  int // level of nesting
	BlockStart bool
	BlockEnd   bool

	Func        bool // true if it's a function call
	FuncName    string
	Args        []string
	FuncResults []string
	//
	Comparison bool // true if it's a comparison
	Negated    bool
	Left       string
	Right      string
	//
	JumpIf  bool // true if it's conditional jump
	IfTrue  bool
	IfFalse bool
	//
	Condition         bool // true if it's a condition
	ConditionIn       bool
	ConditionContains bool
	// used for comparisons, conditional jumps and conditions
	StrConditionResult string
	ConditionResult    *bool // should always be present for conditions

	//
	Finalized bool // used when a node is finalized, we already fetched result from next OP
}

func (o *OpOutput) String() string {
	ret := fmt.Sprintf("%*c", o.CodeDepth, ' ')
	if o.Code != "" {
		ret += fmt.Sprintf("[%s]", o.Code)
	}

	ret += " "

	switch {
	case o.BlockStart:
		ret = fmt.Sprintf("%*cBLOCK_START [%s]", o.CodeDepth-IndentStep, ' ', o.Code)
		return ret
	case o.BlockEnd:
		indent := max(o.CodeDepth-(IndentStep*2), 0)

		ret = fmt.Sprintf("%*cBLOCK_END [%s]", indent, ' ', o.Code)

		if o.StrConditionResult != "" {
			ret += fmt.Sprintf(" -> %s", o.StrConditionResult)
		}

		return ret
		// A block end can carry a value, for example if it's a count, any, all etc. XXX
	case o.Func:
		return ret + fmt.Sprintf("%s(%s) = %s", o.FuncName, strings.Join(o.Args, ", "), strings.Join(o.FuncResults, ", "))
	case o.Comparison:
		if o.Negated {
			ret += "NOT "
		}

		ret += fmt.Sprintf("%s == %s -> %s", o.Left, o.Right, o.StrConditionResult)

		return ret
	case o.ConditionIn:
		return ret + fmt.Sprintf("%s in %s -> %s", o.Args[0], o.Args[1], o.StrConditionResult)
	case o.ConditionContains:
		return ret + fmt.Sprintf("%s contains %s -> %s", o.Args[0], o.Args[1], o.StrConditionResult)
	case o.JumpIf && o.IfTrue:
		if o.ConditionResult != nil {
			if *o.ConditionResult {
				return ret + "OR -> false"
			}

			return ret + "OR -> true"
		}

		return ret + "OR(?)"
	case o.JumpIf && o.IfFalse:
		if o.ConditionResult != nil {
			if *o.ConditionResult {
				return ret + "AND -> true"
			}

			return ret + "AND -> false"
		}

		return ret + "AND(?)"
	}

	return ret + ""
}

func (ExprRuntimeDebug) extractCode(ip int, program *vm.Program) string {
	locations := program.Locations()
	src := program.Source().String()

	currentInstruction := locations[ip]

	var closest *file.Location

	for i := ip + 1; i < len(locations); i++ {
		if locations[i].From > currentInstruction.From {
			if closest == nil || locations[i].From < closest.From {
				closest = &locations[i]
			}
		}
	}

	var end int
	if closest == nil {
		end = len(src)
	} else {
		end = closest.From
	}

	return cleanTextForDebug(src[locations[ip].From:end])
}

func autoQuote(v any) string {
	switch x := v.(type) {
	case string:
		// let's avoid printing long strings. it can happen ie. when we are debugging expr with `File()` or similar helpers
		if len(x) > 40 {
			return fmt.Sprintf("%q", x[:40]+"...")
		}

		return fmt.Sprintf("%q", x)
	default:
		return fmt.Sprintf("%v", x)
	}
}

type opHandler func(out OpOutput, prevOut *OpOutput, ip int, parts []string, vm *vm.VM, program *vm.Program) *OpOutput

var opHandlers = map[string]opHandler{
	"OpBegin":       opBegin,
	"OpEnd":         opEnd,
	"OpNot":         opNot,
	"OpTrue":        opTrue,
	"OpFalse":       opFalse,
	"OpJumpIfTrue":  opJumpIfTrue,
	"OpJumpIfFalse": opJumpIfFalse,
	"OpCall1":       opCall1,
	"OpCall2":       opCall2,
	"OpCall3":       opCall3,
	"OpCallFast":    opCallFast,
	"OpCallTyped":   opCallTyped,
	"OpCallN":       opCallN,
	"OpEqualString": opEqual,
	"OpEqual":       opEqual,
	"OpEqualInt":    opEqual,
	"OpIn":          opIn,
	"OpContains":    opContains,
}

func opBegin(out OpOutput, _ *OpOutput, _ int, _ []string, _ *vm.VM, _ *vm.Program) *OpOutput {
	out.CodeDepth += IndentStep
	out.BlockStart = true

	return &out
}

func opEnd(out OpOutput, _ *OpOutput, _ int, _ []string, vm *vm.VM, _ *vm.Program) *OpOutput {
	out.CodeDepth -= IndentStep
	out.BlockEnd = true

	// OpEnd can carry value, if it's any/all/count etc.
	if len(vm.Stack) > 0 {
		out.StrConditionResult = fmt.Sprintf("%v", vm.Stack)
	}

	return &out
}

func opNot(_ OpOutput, prevOut *OpOutput, _ int, _ []string, _ *vm.VM, _ *vm.Program) *OpOutput {
	// negate the previous condition
	prevOut.Negated = true
	return nil
}

func opTrue(out OpOutput, _ *OpOutput, _ int, _ []string, _ *vm.VM, _ *vm.Program) *OpOutput {
	// generated when possible ? (1 == 1)
	out.Condition = true
	out.ConditionResult = new(bool)
	*out.ConditionResult = true
	out.StrConditionResult = "true"

	return &out
}

func opFalse(out OpOutput, _ *OpOutput, _ int, _ []string, _ *vm.VM, _ *vm.Program) *OpOutput {
	// generated when possible ? (1 != 1)
	out.Condition = true
	out.ConditionResult = new(bool)
	*out.ConditionResult = false
	out.StrConditionResult = "false"

	return &out
}

func opJumpIfTrue(out OpOutput, _ *OpOutput, _ int, _ []string, vm *vm.VM, _ *vm.Program) *OpOutput {
	stack := vm.Stack
	out.JumpIf = true
	out.IfTrue = true
	out.StrConditionResult = fmt.Sprintf("%v", stack[0])

	if val, ok := stack[0].(bool); ok {
		out.ConditionResult = new(bool)
		*out.ConditionResult = val
	}

	return &out
}

func opJumpIfFalse(out OpOutput, _ *OpOutput, _ int, _ []string, vm *vm.VM, _ *vm.Program) *OpOutput {
	stack := vm.Stack
	out.JumpIf = true
	out.IfFalse = true
	out.StrConditionResult = fmt.Sprintf("%v", stack[0])

	if val, ok := stack[0].(bool); ok {
		out.ConditionResult = new(bool)
		*out.ConditionResult = val
	}

	return &out
}

func opCall1(out OpOutput, _ *OpOutput, _ int, parts []string, vm *vm.VM, _ *vm.Program) *OpOutput {
	out.Func = true
	out.FuncName = parts[3]
	stack := vm.Stack

	num_items := 1
	for i := len(stack) - 1; i >= 0 && num_items > 0; i-- {
		out.Args = append(out.Args, autoQuote(stack[i]))
		num_items--
	}

	return &out
}

func opCall2(out OpOutput, _ *OpOutput, _ int, parts []string, vm *vm.VM, _ *vm.Program) *OpOutput {
	out.Func = true
	out.FuncName = parts[3]
	stack := vm.Stack

	num_items := 2
	for i := len(stack) - 1; i >= 0 && num_items > 0; i-- {
		out.Args = append(out.Args, autoQuote(stack[i]))
		num_items--
	}

	return &out
}

func opCall3(out OpOutput, _ *OpOutput, _ int, parts []string, vm *vm.VM, _ *vm.Program) *OpOutput {
	out.Func = true
	out.FuncName = parts[3]
	stack := vm.Stack

	num_items := 3
	for i := len(stack) - 1; i >= 0 && num_items > 0; i-- {
		out.Args = append(out.Args, autoQuote(stack[i]))
		num_items--
	}

	return &out
}

func opCallFast(_ OpOutput, _ *OpOutput, _ int, _ []string, _ *vm.VM, _ *vm.Program) *OpOutput {
	// double check OpCallFast and OpCallTyped
	return nil
}

func opCallTyped(_ OpOutput, _ *OpOutput, _ int, _ []string, _ *vm.VM, _ *vm.Program) *OpOutput {
	// double check OpCallFast and OpCallTyped
	return nil
}

func opCallN(out OpOutput, _ *OpOutput, ip int, parts []string, vm *vm.VM, program *vm.Program) *OpOutput {
	// Op for function calls with more than 3 args
	out.Func = true
	out.FuncName = parts[1]
	stack := vm.Stack

	// for OpCallN, we get the number of args
	if len(program.Arguments) >= ip {
		nb_args := program.Arguments[ip]
		if nb_args > 0 {
			// we need to skip the top item on stack
			for i := len(stack) - 2; i >= 0 && nb_args > 0; i-- {
				out.Args = append(out.Args, autoQuote(stack[i]))
				nb_args--
			}
		}
	} else { // let's blindly take the items on stack
		for _, val := range vm.Stack {
			out.Args = append(out.Args, autoQuote(val))
		}
	}

	return &out
}

func opEqual(out OpOutput, _ *OpOutput, _ int, _ []string, vm *vm.VM, _ *vm.Program) *OpOutput {
	stack := vm.Stack
	out.Comparison = true
	out.Left = autoQuote(stack[0])
	out.Right = autoQuote(stack[1])

	return &out
}

func opIn(out OpOutput, _ *OpOutput, _ int, _ []string, vm *vm.VM, _ *vm.Program) *OpOutput {
	// in operator
	stack := vm.Stack
	out.Condition = true
	out.ConditionIn = true
	// it seems that we tend to receive stack[1] as a map.
	// it is tempting to use reflect to extract keys, but we end up with an array that doesn't match the initial order
	// (because of the random order of the map)
	out.Args = append(out.Args, autoQuote(stack[0]))
	out.Args = append(out.Args, autoQuote(stack[1]))

	return &out
}

func opContains(out OpOutput, _ *OpOutput, _ int, _ []string, vm *vm.VM, _ *vm.Program) *OpOutput {
	// kind of OpIn, but reverse
	stack := vm.Stack
	out.Condition = true
	out.ConditionContains = true
	// it seems that we tend to receive stack[1] as a map.
	// it is tempting to use reflect to extract keys, but we end up with an array that doesn't match the initial order
	// (because of the random order of the map)
	out.Args = append(out.Args, autoQuote(stack[0]))
	out.Args = append(out.Args, autoQuote(stack[1]))

	return &out
}

func (erp ExprRuntimeDebug) ipDebug(ip int, vm *vm.VM, program *vm.Program, parts []string, outputs []OpOutput) []OpOutput {
	IdxOut := len(outputs)
	prevIdxOut := 0
	currentDepth := 0

	// when there is a function call or comparison, we need to wait for the next instruction to get the result and "finalize" the previous one
	if IdxOut > 0 {
		prevIdxOut = IdxOut - 1
		currentDepth = outputs[prevIdxOut].CodeDepth

		if outputs[prevIdxOut].Func && !outputs[prevIdxOut].Finalized {
			stack := vm.Stack
			num_items := 1

			for i := len(stack) - 1; i >= 0 && num_items > 0; i-- {
				outputs[prevIdxOut].FuncResults = append(outputs[prevIdxOut].FuncResults, autoQuote(stack[i]))
				num_items--
			}

			outputs[prevIdxOut].Finalized = true
		} else if (outputs[prevIdxOut].Comparison || outputs[prevIdxOut].Condition) && !outputs[prevIdxOut].Finalized {
			stack := vm.Stack
			outputs[prevIdxOut].StrConditionResult = fmt.Sprintf("%+v", stack)

			if val, ok := stack[0].(bool); ok {
				outputs[prevIdxOut].ConditionResult = new(bool)
				*outputs[prevIdxOut].ConditionResult = val
			}

			outputs[prevIdxOut].Finalized = true
		}
	}

	erp.Logger.Tracef("[STEP %d:%s] (stack:%+v) (parts:%+v) {depth:%d}", ip, parts[1], vm.Stack, parts, currentDepth)

	var prevOut *OpOutput

	if handler, ok := opHandlers[parts[1]]; ok {
		if len(outputs) > 0 {
			prevOut = &outputs[prevIdxOut]
		}

		out := handler(
			OpOutput{
				CodeDepth: currentDepth,
				Code:      erp.extractCode(ip, program),
			},
			prevOut,
			ip, parts, vm, program)

		if out != nil {
			outputs = append(outputs, *out)
		}
	}

	return outputs
}

func (erp ExprRuntimeDebug) ipSeek(ip int) []string {
	for i := range len(erp.Lines) {
		parts := strings.Fields(erp.Lines[i])
		if len(parts) == 0 {
			continue
		}

		if parts[0] == strconv.Itoa(ip) {
			return parts
		}
	}

	return nil
}

func Run(program *vm.Program, env any, logger *log.Entry, debug bool) (any, error) {
	if debug {
		dbgInfo, ret, err := RunWithDebug(program, env, logger)
		DisplayExprDebug(program, dbgInfo, logger, ret)

		return ret, err
	}

	return expr.Run(program, env)
}

func cleanTextForDebug(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	text = strings.Trim(text, " \t\n")

	return text
}

func DisplayExprDebug(program *vm.Program, outputs []OpOutput, logger *log.Entry, ret any) {
	logger.Debugf("dbg(result=%v): %s", ret, cleanTextForDebug(program.Source().String()))

	for _, output := range outputs {
		logger.Debugf("%s", output.String())
	}
}

// TBD: Based on the level of the logger (ie. trace vs debug) we could decide to add more low level instructions (pop, push, etc.)
func RunWithDebug(program *vm.Program, env any, logger *log.Entry) ([]OpOutput, any, error) {
	outputs := []OpOutput{}
	erp := ExprRuntimeDebug{
		Logger: logger,
	}
	vm := vm.Debug()
	opcodes := program.Disassemble()
	lines := strings.Split(opcodes, "\n")
	erp.Lines = lines

	go func() {
		// We must never return until the execution of the program is done
		erp.Logger.Tracef("[START] ip 0")

		ops := erp.ipSeek(0)
		if ops == nil {
			log.Warningf("error while debugging expr: failed getting ops for ip 0")
		}

		outputs = erp.ipDebug(0, vm, program, ops, outputs)

		vm.Step()

		for ip := range vm.Position() {
			ops := erp.ipSeek(ip)
			if ops == nil {
				erp.Logger.Tracef("[DONE] ip %d", ip)
				break
			}

			outputs = erp.ipDebug(ip, vm, program, ops, outputs)

			vm.Step()
		}
	}()

	var return_error error

	ret, err := vm.Run(program, env)
	// if the expr runtime failed, we don't need to wait for the debug to finish
	if err != nil {
		return_error = err
	}
	// the overall result of expression is the result of last op ?
	if len(outputs) > 0 {
		lastOutIdx := len(outputs)
		if lastOutIdx > 0 {
			lastOutIdx -= 1
		}

		switch val := ret.(type) {
		case bool:
			log.Tracef("completing with bool %t", ret)
			// if outputs[lastOutIdx].Comparison {
			outputs[lastOutIdx].StrConditionResult = fmt.Sprintf("%v", ret)
			outputs[lastOutIdx].ConditionResult = new(bool)
			*outputs[lastOutIdx].ConditionResult = val
			outputs[lastOutIdx].Finalized = true
		default:
			log.Tracef("completing with type %T -> %v", ret, ret)
			outputs[lastOutIdx].StrConditionResult = fmt.Sprintf("%v", ret)
			outputs[lastOutIdx].Finalized = true
		}
	} else {
		log.Tracef("no output from expr runtime")
	}

	return outputs, ret, return_error
}
