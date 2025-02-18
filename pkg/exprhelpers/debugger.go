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
		indent := o.CodeDepth - (IndentStep * 2)
		if indent < 0 {
			indent = 0
		}

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

func (erp ExprRuntimeDebug) extractCode(ip int, program *vm.Program) string {
	locations := program.Locations()
	src := string(program.Source())

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

func (erp ExprRuntimeDebug) ipDebug(ip int, vm *vm.VM, program *vm.Program, parts []string, outputs []OpOutput) ([]OpOutput, error) {
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

	out := OpOutput{}
	out.CodeDepth = currentDepth
	out.Code = erp.extractCode(ip, program)

	switch parts[1] {
	case "OpBegin":
		out.CodeDepth += IndentStep
		out.BlockStart = true
		outputs = append(outputs, out)
	case "OpEnd":
		out.CodeDepth -= IndentStep
		out.BlockEnd = true
		// OpEnd can carry value, if it's any/all/count etc.
		if len(vm.Stack) > 0 {
			out.StrConditionResult = fmt.Sprintf("%v", vm.Stack)
		}

		outputs = append(outputs, out)
	case "OpNot":
		// negate the previous condition
		outputs[prevIdxOut].Negated = true
	case "OpTrue": // generated when possible ? (1 == 1)
		out.Condition = true
		out.ConditionResult = new(bool)
		*out.ConditionResult = true
		out.StrConditionResult = "true"
		outputs = append(outputs, out)
	case "OpFalse": // generated when possible ? (1 != 1)
		out.Condition = true
		out.ConditionResult = new(bool)
		*out.ConditionResult = false
		out.StrConditionResult = "false"
		outputs = append(outputs, out)
	case "OpJumpIfTrue": // OR
		stack := vm.Stack
		out.JumpIf = true
		out.IfTrue = true
		out.StrConditionResult = fmt.Sprintf("%v", stack[0])

		if val, ok := stack[0].(bool); ok {
			out.ConditionResult = new(bool)
			*out.ConditionResult = val
		}

		outputs = append(outputs, out)
	case "OpJumpIfFalse": // AND
		stack := vm.Stack
		out.JumpIf = true
		out.IfFalse = true
		out.StrConditionResult = fmt.Sprintf("%v", stack[0])

		if val, ok := stack[0].(bool); ok {
			out.ConditionResult = new(bool)
			*out.ConditionResult = val
		}

		outputs = append(outputs, out)
	case "OpCall1": // Op for function calls
		out.Func = true
		out.FuncName = parts[3]
		stack := vm.Stack

		num_items := 1
		for i := len(stack) - 1; i >= 0 && num_items > 0; i-- {
			out.Args = append(out.Args, autoQuote(stack[i]))
			num_items--
		}

		outputs = append(outputs, out)
	case "OpCall2": // Op for function calls
		out.Func = true
		out.FuncName = parts[3]
		stack := vm.Stack

		num_items := 2
		for i := len(stack) - 1; i >= 0 && num_items > 0; i-- {
			out.Args = append(out.Args, autoQuote(stack[i]))
			num_items--
		}

		outputs = append(outputs, out)
	case "OpCall3": // Op for function calls
		out.Func = true
		out.FuncName = parts[3]
		stack := vm.Stack

		num_items := 3
		for i := len(stack) - 1; i >= 0 && num_items > 0; i-- {
			out.Args = append(out.Args, autoQuote(stack[i]))
			num_items--
		}

		outputs = append(outputs, out)
	// double check OpCallFast and OpCallTyped
	case "OpCallFast", "OpCallTyped":
		//
	case "OpCallN": // Op for function calls with more than 3 args
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

		outputs = append(outputs, out)
	case "OpEqualString", "OpEqual", "OpEqualInt": // comparisons
		stack := vm.Stack
		out.Comparison = true
		out.Left = autoQuote(stack[0])
		out.Right = autoQuote(stack[1])
		outputs = append(outputs, out)
	case "OpIn": // in operator
		stack := vm.Stack
		out.Condition = true
		out.ConditionIn = true
		//seems that we tend to receive stack[1] as a map.
		//it is tempting to use reflect to extract keys, but we end up with an array that doesn't match the initial order
		//(because of the random order of the map)
		out.Args = append(out.Args, autoQuote(stack[0]))
		out.Args = append(out.Args, autoQuote(stack[1]))
		outputs = append(outputs, out)
	case "OpContains": // kind OpIn , but reverse
		stack := vm.Stack
		out.Condition = true
		out.ConditionContains = true
		//seems that we tend to receive stack[1] as a map.
		//it is tempting to use reflect to extract keys, but we end up with an array that doesn't match the initial order
		//(because of the random order of the map)
		out.Args = append(out.Args, autoQuote(stack[0]))
		out.Args = append(out.Args, autoQuote(stack[1]))
		outputs = append(outputs, out)
	}

	return outputs, nil
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

func Run(program *vm.Program, env interface{}, logger *log.Entry, debug bool) (any, error) {
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
	logger.Debugf("dbg(result=%v): %s", ret, cleanTextForDebug(string(program.Source())))

	for _, output := range outputs {
		logger.Debugf("%s", output.String())
	}
}

// TBD: Based on the level of the logger (ie. trace vs debug) we could decide to add more low level instructions (pop, push, etc.)
func RunWithDebug(program *vm.Program, env interface{}, logger *log.Entry) ([]OpOutput, any, error) {
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
		var err error

		erp.Logger.Tracef("[START] ip 0")

		ops := erp.ipSeek(0)
		if ops == nil {
			log.Warningf("error while debugging expr: failed getting ops for ip 0")
		}

		if outputs, err = erp.ipDebug(0, vm, program, ops, outputs); err != nil {
			log.Warningf("error while debugging expr: error while debugging at ip 0")
		}

		vm.Step()

		for ip := range vm.Position() {
			ops := erp.ipSeek(ip)
			if ops == nil {
				erp.Logger.Tracef("[DONE] ip %d", ip)
				break
			}

			if outputs, err = erp.ipDebug(ip, vm, program, ops, outputs); err != nil {
				log.Warningf("error while debugging expr: error while debugging at ip %d", ip)
			}

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
