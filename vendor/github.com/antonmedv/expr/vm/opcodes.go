package vm

type Opcode byte

const (
	OpPush Opcode = iota
	OpPushInt
	OpPop
	OpLoadConst
	OpLoadField
	OpLoadFast
	OpLoadMethod
	OpLoadFunc
	OpFetch
	OpFetchField
	OpMethod
	OpTrue
	OpFalse
	OpNil
	OpNegate
	OpNot
	OpEqual
	OpEqualInt
	OpEqualString
	OpJump
	OpJumpIfTrue
	OpJumpIfFalse
	OpJumpIfNil
	OpJumpIfNotNil
	OpJumpIfEnd
	OpJumpBackward
	OpIn
	OpLess
	OpMore
	OpLessOrEqual
	OpMoreOrEqual
	OpAdd
	OpSubtract
	OpMultiply
	OpDivide
	OpModulo
	OpExponent
	OpRange
	OpMatches
	OpMatchesConst
	OpContains
	OpStartsWith
	OpEndsWith
	OpSlice
	OpCall
	OpCall0
	OpCall1
	OpCall2
	OpCall3
	OpCallN
	OpCallFast
	OpCallTyped
	OpBuiltin
	OpArray
	OpMap
	OpLen
	OpCast
	OpDeref
	OpIncrementIt
	OpIncrementCount
	OpGetCount
	OpGetLen
	OpPointer
	OpBegin
	OpEnd // This opcode must be at the end of this list.
)
