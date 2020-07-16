package main

func inSlice(s string, slice []string) bool {
	for _, str := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func indexOf(s string, slice []string) int {
	for i, elem := range slice {
		if s == elem {
			return i
		}
	}
	return -1
}
