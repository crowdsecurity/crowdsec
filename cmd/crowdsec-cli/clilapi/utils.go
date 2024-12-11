package clilapi

func removeFromSlice(val string, slice []string) []string {
	var i int
	var value string

	valueFound := false

	// get the index
	for i, value = range slice {
		if value == val {
			valueFound = true
			break
		}
	}

	if valueFound {
		slice[i] = slice[len(slice)-1]
		slice[len(slice)-1] = ""
		slice = slice[:len(slice)-1]
	}

	return slice
}
