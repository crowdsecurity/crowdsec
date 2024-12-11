package ask

import (
	"github.com/AlecAivazis/survey/v2"
)

func YesNo(message string, defaultAnswer bool) (bool, error) {
	var answer bool

	prompt := &survey.Confirm{
		Message: message,
		Default: defaultAnswer,
	}

	if err := survey.AskOne(prompt, &answer); err != nil {
		return defaultAnswer, err
	}

	return answer, nil
}
