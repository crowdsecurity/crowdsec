package hubops

import (
	"strings"

	"github.com/fatih/color"

	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

// colorizeItemName splits the input string on "/" and colorizes the second part.
func colorizeItemName(fullname string) string {
	parts := strings.SplitN(fullname, "/", 2)
	if len(parts) == 2 {
		bold := color.New(color.Bold)
		author := parts[0]
		name := parts[1]
		return author + "/" + bold.Sprint(name)
	}
	return fullname
}

func colorizeOpType(opType string) string {
	switch opType {
	case (&DownloadCommand{}).OperationType():
		return emoji.InboxTray + " " + color.BlueString(opType)
	case (&EnableCommand{}).OperationType():
		return emoji.CheckMarkButton + " " + color.GreenString(opType)
	case (&DisableCommand{}).OperationType():
		return emoji.CrossMark + " " + color.RedString(opType)
	case (&PurgeCommand{}).OperationType():
		return emoji.Wastebasket + " " + color.RedString(opType)
	case (&DataRefreshCommand{}).OperationType():
		return emoji.Sync + " " + opType
	}

	return opType
}
