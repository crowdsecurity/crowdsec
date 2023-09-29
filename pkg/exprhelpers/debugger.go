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

var IndentStep = 4

// we use this struct to store the output of the expr runtime
type OpOutput struct {
	Code string //relevant code part

	CodeDepth  int //level of nesting
	BlockStart bool
	BlockEnd   bool

	Func        bool //true if it's a function call
	FuncName    string
	Args        []string
	FuncResults []string
	//
	Comparison bool //true if it's a comparison
	Negated    bool
	Left       string
	Right      string
	//
	JumpIf  bool //true if it's conditional jump
	IfTrue  bool
	IfFalse bool
	//
	Condition   bool //true if it's a condition
	ConditionIn bool
	//used for comparisons, conditional jumps and conditions
	StrConditionResult string
	ConditionResult    *bool //should always be present for conditions

	//
	Finalized bool //used when a node is finalized, we already fetched result from next OP
}

func (o *OpOutput) String() string {

	ret := fmt.Sprintf("%*c", o.CodeDepth, ' ')
	if len(o.Code) != 0 {
		ret += fmt.Sprintf("[%s]", o.Code)
	}
	ret += " "
	if o.BlockStart {
		ret = fmt.Sprintf("%*cBLOCK_START [%s]", o.CodeDepth, ' ', o.Code)
		return ret
	}
	if o.BlockEnd {
		ret = fmt.Sprintf("%*cBLOCK_END [%s]", o.CodeDepth-IndentStep, ' ', o.Code)
		if len(o.StrConditionResult) > 0 {
			ret += fmt.Sprintf(" -> %s", o.StrConditionResult)
		}
		return ret
		//A block end can carry a value, for example if it's a count, any, all etc. XXX

	}
	if o.Func {
		return ret + fmt.Sprintf("%s(%s) = %s", o.FuncName, strings.Join(o.Args, ", "), strings.Join(o.FuncResults, ", "))

	}
	if o.Comparison {
		if o.Negated {
			ret += "NOT "
		}
		ret += fmt.Sprintf("%s == %s -> %s", o.Left, o.Right, o.StrConditionResult)
		return ret
	}
	if o.ConditionIn {
		return ret + fmt.Sprintf("%s in %s -> %s", o.Args[0], o.Args[1], o.StrConditionResult)
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
	return ret + ""
}

func (erp ExprRuntimeDebug) extractCode(ip int, program *vm.Program, parts []string) string {

	if program.Locations[ip].Line == 0 { //it seems line is zero when it's not actual code (ie. op push at the begining)
		return ""
	}
	startLine := program.Locations[ip].Line - 1
	startColumn := program.Locations[ip].Column
	endLine := startLine
	lines := strings.Split(program.Source.Content(), "\n")
	log.Tracef(" start offset : %d, %d", startLine, startColumn)

	//by default we go to end of line
	endColumn := len(lines[endLine])

	//we seek the next OP with a diff code offset
	for i := ip + 1; i < len(program.Locations); i++ {
		if program.Locations[i].Line > program.Locations[ip].Line {
			endLine = program.Locations[i].Line - 1
			endColumn = program.Locations[i].Column
			break
		}
		if program.Locations[i].Line == program.Locations[ip].Line &&
			program.Locations[i].Column > program.Locations[ip].Column {
			endColumn = program.Locations[i].Column
			break
		}
	}
	code_snippet := ""
	for i := startLine; i <= endLine; i++ {
		//log.Tracef("collecting, line %d, len: %d", i, len(lines[i]))
		if i == startLine {
			if startLine != endLine {
				code_snippet += lines[i][startColumn:]
				continue
			} else {
				//log.Tracef("adding data from line %d from %d to %d", i, startColumn, endColumn)
				code_snippet += lines[i][startColumn:endColumn]
				break
			}
		}
		if i == endLine {
			code_snippet += lines[i][:endColumn]
			break
		}
		code_snippet += lines[i]
	}

	//log.Tracef(" end offset :  %d - %d", endLine, endColumn)
	//log.Tracef(" snippet    : '%s'", code_snippet)
	log.Tracef("#code extract for ip %d [%s] -> '%s'", ip, parts[1], code_snippet)
	return code_snippet
}

func (erp ExprRuntimeDebug) ipDebug(ip int, vm *vm.VM, program *vm.Program, parts []string, outputs []OpOutput) ([]OpOutput, error) {

	IdxOut := len(outputs)
	prevIdxOut := 0
	currentDepth := 0

	//when there is a function call or comparison, we need to wait for the next instruction to get the result and "finalize" the previous one
	if IdxOut > 0 {
		prevIdxOut = IdxOut - 1
		//log.Tracef("extracted depth %d from previous instruction (%d)", outputs[prevIdxOut].CodeDepth, prevIdxOut)
		currentDepth = outputs[prevIdxOut].CodeDepth
		//log.Tracef("Complete previous item ? [stack:%+v]", vm.Stack())
		if outputs[prevIdxOut].Func && !outputs[prevIdxOut].Finalized {
			//erp.Logger.Tracef("previous op was func call, setting result of %d to %v", prevIdxOut, vm.Stack())
			for _, val := range vm.Stack() {
				outputs[prevIdxOut].FuncResults = append(outputs[prevIdxOut].FuncResults, fmt.Sprintf("%v", val))
				outputs[prevIdxOut].Finalized = true
			}
		} else if outputs[prevIdxOut].Comparison && !outputs[prevIdxOut].Finalized {
			stack := vm.Stack()
			//erp.Logger.Tracef("previous op was comparison, setting result of %d to %v", prevIdxOut, vm.Stack())
			outputs[prevIdxOut].StrConditionResult = fmt.Sprintf("%+v", stack)
			switch stack[0].(type) {
			case bool:
				outputs[prevIdxOut].ConditionResult = new(bool)
				*outputs[prevIdxOut].ConditionResult = stack[0].(bool)
			}
			outputs[prevIdxOut].Finalized = true
		}
	}

	erp.Logger.Tracef("[STEP %d:%s] (stack:%+v) (parts:%+v) {depth:%d}", ip, parts[1], vm.Stack(), parts, currentDepth)
	out := OpOutput{}
	out.CodeDepth = currentDepth
	out.Code = erp.extractCode(ip, program, parts)

	switch parts[1] {
	case "OpBegin":
		out.CodeDepth += IndentStep
		out.BlockStart = true
		outputs = append(outputs, out)
	case "OpEnd":
		out.CodeDepth -= IndentStep
		out.BlockEnd = true
		//OpEnd can carry value, if it's any/all/count etc.
		if len(vm.Stack()) > 0 {
			out.StrConditionResult = fmt.Sprintf("%v", vm.Stack())
		}
		outputs = append(outputs, out)
	case "OpNot":
		//negate the previous condition
		outputs[prevIdxOut].Negated = true
	case "OpTrue": //generated when possible ? (1 == 1)
		out.Condition = true
		out.ConditionResult = new(bool)
		*out.ConditionResult = true
		out.StrConditionResult = "true"
		outputs = append(outputs, out)
	case "OpFalse": //generated when possible ? (1 != 1)
		out.Condition = true
		out.ConditionResult = new(bool)
		*out.ConditionResult = false
		out.StrConditionResult = "false"
		outputs = append(outputs, out)
	case "OpJumpIfTrue": //OR
		stack := vm.Stack()
		out.JumpIf = true
		out.IfTrue = true
		out.StrConditionResult = fmt.Sprintf("%v", stack[0])
		switch stack[0].(type) {
		case bool:
			out.ConditionResult = new(bool)
			*out.ConditionResult = stack[0].(bool)
		}
		outputs = append(outputs, out)
	case "OpJumpIfFalse": //AND
		stack := vm.Stack()
		out.JumpIf = true
		out.IfFalse = true
		out.StrConditionResult = fmt.Sprintf("%v", stack[0])
		switch stack[0].(type) {
		case bool:
			out.ConditionResult = new(bool)
			*out.ConditionResult = stack[0].(bool)
		}
		outputs = append(outputs, out)
	case "OpCall1", "OpCall2", "OpCall3", "OpCallN", "OpCallFast", "OpCallTyped": //Op for function calls
		out.Func = true
		out.FuncName = parts[3]
		for _, val := range vm.Stack() {
			out.Args = append(out.Args, fmt.Sprintf("%v", val))
		}
		outputs = append(outputs, out)
	case "OpEqualString", "OpEqual", "OpEqualInt": //comparisons

		stack := vm.Stack()
		out.Comparison = true
		out.Left = fmt.Sprintf("%v", stack[0])
		out.Right = fmt.Sprintf("%v", stack[1])
		outputs = append(outputs, out)
	case "OpIn": //in operator
		stack := vm.Stack()
		out.Condition = true
		out.ConditionIn = true
		out.Args = append(out.Args, fmt.Sprintf("%v", stack[0]))
		//seems that we tend to receive stack[1] as a map.
		//it is tempting to use reflect to extract keys, but we end up with an array that doesn't match the initial order
		//(because of the random order of the map)
		out.Args = append(out.Args, fmt.Sprintf("%v", stack[1]))
		outputs = append(outputs, out)
	}
	return outputs, nil
}

func (erp ExprRuntimeDebug) ipSeek(ip int) []string {
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
		DisplayExprDebug(program, dbgInfo, logger, ret)
		return ret, err
	} else {
		return expr.Run(program, env)

	}
}

func DisplayExprDebug(program *vm.Program, outputs []OpOutput, logger *log.Entry, ret any) {
	logger.Debugf("dbg(result=%v): %s", ret, program.Source.Content())
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
	//log.Tracef("------")
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
	if len(outputs) > 0 {
		lastOutIdx := len(outputs)
		if lastOutIdx > 0 {
			lastOutIdx = lastOutIdx - 1
		}
		switch ret.(type) {
		case bool:
			log.Tracef("completing with bool %t", ret)
			//if outputs[lastOutIdx].Comparison {
			outputs[lastOutIdx].StrConditionResult = fmt.Sprintf("%v", ret)
			outputs[lastOutIdx].ConditionResult = new(bool)
			*outputs[lastOutIdx].ConditionResult = ret.(bool)
			// } else if outputs[lastOutIdx].Func {

			// }
			outputs[lastOutIdx].Finalized = true
		default:
			log.Tracef("completing with type %T -> %v", ret, ret)
			outputs[lastOutIdx].StrConditionResult = fmt.Sprintf("%v", ret)
			outputs[lastOutIdx].Finalized = true
		}
	} else {
		log.Tracef("no output from expr runtime")
	}
	return outputs, ret, nil
}
