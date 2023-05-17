package table

import "strings"

func align(input ansiBlob, width int, a Alignment) ansiBlob {
	padSize := width - input.Len()
	if padSize <= 0 {
		return input
	}
	switch a {
	case AlignRight:
		return newANSI(strings.Repeat(" ", padSize) + input.String())
	case AlignCenter:
		leftPad := padSize / 2
		rightPad := padSize - leftPad
		if leftPad > 0 {
			input = newANSI(strings.Repeat(" ", leftPad) + input.String())
		}
		if rightPad > 0 {
			input = newANSI(input.String() + strings.Repeat(" ", rightPad))
		}
		return input
	default: // left by default
		return newANSI(input.String() + strings.Repeat(" ", padSize))
	}
}

func wrapText(input string, wrapSize int) []ansiBlob {
	var words []ansiBlob
	lines := strings.Split(input, "\n")
	for _, in := range lines {
		if len(words) > 0 {
			words = append(words, ansiBlob{{value: "\n"}})
		}
		in = strings.TrimSpace(in)
		lineWords := newANSI(in).Words()
		for _, word := range lineWords {
			// word won't fit on a line by itself, so split it
			for word.Len() > wrapSize {
				before, after := word.Cut(wrapSize - 1)
				word = after
				words = append(words, newANSI(before.String()+"-"))
			}
			if word.Len() > 0 {
				words = append(words, word)
			}
		}
	}

	var output []ansiBlob
	var current ansiBlob

	for _, word := range words {

		available := wrapSize - current.Len()

		switch {
		case word.String() == "\n":
			output = append(output, current.TrimSpace())
			current = newANSI("")
		case available == 0: // no room left on line, start a new one with the word added to it
			output = append(output, current.TrimSpace())
			current = word
			if current.Len() < wrapSize {
				current = newANSI(current.String() + " ")
			}
		case current.Len()+word.Len() == wrapSize: // word fits on line exactly, add it
			current = newANSI(current.String() + word.String())
		case current.Len()+word.Len() < wrapSize: // word fits on line, add it with a space afterwards
			current = newANSI(current.String() + word.String() + " ")
		default: // word won't fit so start a new line
			output = append(output, current.TrimSpace())
			current = word
			if current.Len() < wrapSize {
				current = newANSI(current.String() + " ")
			}
		}
	}
	if current.Len() > 0 {
		output = append(output, current.TrimSpace())
	}

	if len(output) == 0 {
		output = append(output, newANSI(""))
	}

	return output
}
