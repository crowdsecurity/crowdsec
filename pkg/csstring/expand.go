package csstring

func seekClosingBracket(s string, i int) int {
	for ; i < len(s); i++ {
		if s[i] == '}' {
			return i
		}
	}

	return -1
}

func seekEndVarname(s string, i int) int {
	// envvar names are more strict but this is good enough
	for ; i < len(s); i++ {
		if (s[i] < 'a' || s[i] > 'z') && (s[i] < 'A' || s[i] > 'Z') && (s[i] < '0' || s[i] > '9') && s[i] != '_' {
			break
		}
	}

	return i
}

func replaceVarBracket(s string, i int, mapping func(string) (string, bool)) string {
	j := seekClosingBracket(s, i+2)
	if j < 0 {
		return s
	}

	if j < len(s) {
		varName := s[i+2 : j]
		if val, ok := mapping(varName); ok {
			s = s[:i] + val + s[j+1:]
		}
	}

	return s
}

func replaceVar(s string, i int, mapping func(string) (string, bool)) string {
	if s[i+1] == '{' {
		return replaceVarBracket(s, i, mapping)
	}

	j := seekEndVarname(s, i+1)
	if j < 0 {
		return s
	}

	if j > i+1 {
		varName := s[i+1 : j]
		if val, ok := mapping(varName); ok {
			s = s[:i] + val + s[j:]
		}
	}

	return s
}

// StrictExpand replaces ${var} or $var in the string according to the mapping
// function, like os.Expand. The difference is that the mapping function
// returns a boolean indicating whether the variable was found.
// If the variable was not found, the string is not modified.
//
// Whereas os.ExpandEnv uses os.Getenv, here we can use os.LookupEnv
// to distinguish between an empty variable and an undefined one.
func StrictExpand(s string, mapping func(string) (string, bool)) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '$' {
			s = replaceVar(s, i, mapping)
		}
	}

	return s
}
