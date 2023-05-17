package wasm

import (
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/wasmdebug"
)

// ImportedFunctions returns the definitions of each imported function.
//
// Note: Unlike ExportedFunctions, there is no unique constraint on imports.
func (m *Module) ImportedFunctions() (ret []api.FunctionDefinition) {
	for i := range m.FunctionDefinitionSection {
		d := &m.FunctionDefinitionSection[i]
		if d.importDesc != nil {
			ret = append(ret, d)
		}
	}
	return
}

// ExportedFunctions returns the definitions of each exported function.
func (m *Module) ExportedFunctions() map[string]api.FunctionDefinition {
	ret := map[string]api.FunctionDefinition{}
	for i := range m.FunctionDefinitionSection {
		d := &m.FunctionDefinitionSection[i]
		for _, e := range d.exportNames {
			ret[e] = d
		}
	}
	return ret
}

// BuildFunctionDefinitions generates function metadata that can be parsed from
// the module. This must be called after all validation.
//
// Note: This is exported for tests who don't use wazero.Runtime or
// NewHostModule to compile the module.
func (m *Module) BuildFunctionDefinitions() {
	if len(m.FunctionSection) == 0 {
		return
	}

	var moduleName string
	var functionNames NameMap
	var localNames, resultNames IndirectNameMap
	if m.NameSection != nil {
		moduleName = m.NameSection.ModuleName
		functionNames = m.NameSection.FunctionNames
		localNames = m.NameSection.LocalNames
		resultNames = m.NameSection.ResultNames
	}

	importCount := m.ImportFuncCount()
	m.FunctionDefinitionSection = make([]FunctionDefinition, importCount+uint32(len(m.FunctionSection)))

	importFuncIdx := Index(0)
	for i := range m.ImportSection {
		imp := &m.ImportSection[i]
		if imp.Type != ExternTypeFunc {
			continue
		}

		def := &m.FunctionDefinitionSection[importFuncIdx]
		def.importDesc = imp
		def.index = importFuncIdx
		def.funcType = &m.TypeSection[imp.DescFunc]
		importFuncIdx++
	}

	for codeIndex, typeIndex := range m.FunctionSection {
		code := &m.CodeSection[codeIndex]
		idx := importFuncIdx + Index(codeIndex)
		def := &m.FunctionDefinitionSection[idx]
		def.index = idx
		def.funcType = &m.TypeSection[typeIndex]
		def.goFunc = code.GoFunc
	}

	n, nLen := 0, len(functionNames)
	for i := range m.FunctionDefinitionSection {
		d := &m.FunctionDefinitionSection[i]
		// The function name section begins with imports, but can be sparse.
		// This keeps track of how far in the name section we've searched.
		funcIdx := d.index
		var funcName string
		for ; n < nLen; n++ {
			next := functionNames[n]
			if next.Index > funcIdx {
				break // we have function names, but starting at a later index.
			} else if next.Index == funcIdx {
				funcName = next.Name
				break
			}
		}

		d.moduleName = moduleName
		d.name = funcName
		d.debugName = wasmdebug.FuncName(moduleName, funcName, funcIdx)
		d.paramNames = paramNames(localNames, funcIdx, len(d.funcType.Params))
		d.resultNames = paramNames(resultNames, funcIdx, len(d.funcType.Results))

		for i := range m.ExportSection {
			e := &m.ExportSection[i]
			if e.Type == ExternTypeFunc && e.Index == funcIdx {
				d.exportNames = append(d.exportNames, e.Name)
			}
		}
	}
}

// FunctionDefinition implements api.FunctionDefinition
type FunctionDefinition struct {
	moduleName  string
	index       Index
	name        string
	debugName   string
	goFunc      interface{}
	funcType    *FunctionType
	importDesc  *Import
	exportNames []string
	paramNames  []string
	resultNames []string
}

// ModuleName implements the same method as documented on api.FunctionDefinition.
func (f *FunctionDefinition) ModuleName() string {
	return f.moduleName
}

// Index implements the same method as documented on api.FunctionDefinition.
func (f *FunctionDefinition) Index() uint32 {
	return f.index
}

// Name implements the same method as documented on api.FunctionDefinition.
func (f *FunctionDefinition) Name() string {
	return f.name
}

// DebugName implements the same method as documented on api.FunctionDefinition.
func (f *FunctionDefinition) DebugName() string {
	return f.debugName
}

// Import implements the same method as documented on api.FunctionDefinition.
func (f *FunctionDefinition) Import() (moduleName, name string, isImport bool) {
	if f.importDesc != nil {
		importDesc := f.importDesc
		moduleName, name, isImport = importDesc.Module, importDesc.Name, true
	}
	return
}

// ExportNames implements the same method as documented on api.FunctionDefinition.
func (f *FunctionDefinition) ExportNames() []string {
	return f.exportNames
}

// GoFunction implements the same method as documented on api.FunctionDefinition.
func (f *FunctionDefinition) GoFunction() interface{} {
	return f.goFunc
}

// ParamTypes implements api.FunctionDefinition ParamTypes.
func (f *FunctionDefinition) ParamTypes() []ValueType {
	return f.funcType.Params
}

// ParamNames implements the same method as documented on api.FunctionDefinition.
func (f *FunctionDefinition) ParamNames() []string {
	return f.paramNames
}

// ResultTypes implements api.FunctionDefinition ResultTypes.
func (f *FunctionDefinition) ResultTypes() []ValueType {
	return f.funcType.Results
}

// ResultNames implements the same method as documented on api.FunctionDefinition.
func (f *FunctionDefinition) ResultNames() []string {
	return f.resultNames
}
