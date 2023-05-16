![ColoredCobra Logo](https://user-images.githubusercontent.com/8699212/159517235-dd7f8733-20b7-47a8-a1b5-9c91956ca86c.png)

---

**[Cobra](https://github.com/spf13/cobra)** library for creating powerful modern CLI doesn't support color settings for console output. `ColoredCobra` is a small library that allows you to colorize the text output of the Cobra library, making the console output look better.

![ColoredCobra Look](https://user-images.githubusercontent.com/8699212/159517325-faeac756-49b4-4b98-ba40-9764e8549335.png)


`ColoredCobra` provides very simple set of settings that allows you to customize individual parts of Cobra text output by specifying a color for them, as well as bold, italic, underlined styles.

![ColoredCobra Config](https://user-images.githubusercontent.com/8699212/159517387-a82eafa4-a0bb-4bc9-a05a-67b05e6ae15c.png)


It's very easy to add `ColoredCobra` to your project!

---

## Installing

Open terminal and execute:

```bash
go get -u github.com/ivanpirog/coloredcobra
```

## Quick start

Open your `cmd/root.go` and insert this code:

```go
import cc "github.com/ivanpirog/coloredcobra"
```

Or:

```go
import (
    ...
    cc "github.com/ivanpirog/coloredcobra"
)
```

Then put this code at the beginning of the `Execute()` function:

```go
    cc.Init(&cc.Config{
        RootCmd:       rootCmd,
        Headings:      cc.HiCyan + cc.Bold + cc.Underline,
        Commands:      cc.HiYellow + cc.Bold,
        Example:       cc.Italic,
        ExecName:      cc.Bold,
        Flags:         cc.Bold,
    })
```

That's all. Now build your project and see the output of the help command.

## Overview

`Config{}` has just one required parameter `RootCmd`. This is a pointer to the Cobra's root command. Rest of parameters have default values.

Style of any part of text output is represented by a sum of predefined constants. For example:

```go
Headings: cc.HiYellow + cc.Bold + cc.Underline
Commands: cc.Red + cc.Bold
ExecName: cc.Bold      // equals cc.White + cc.Bold
Example:  cc.Underline // equals cc.White + cc.Underline
```

### Available color constants:

```
Black
Red
Green
Yellow
Blue
Magenta
Cyan
White (default)
HiRed (Hi-Intensity Red)
HiGreen
HiYellow
HiBlue
HiMagenta
HiCyan
HiWhite
```

### Available text formatting constants:

```
Bold
Italic
Underline
```

### Available config parameters:

![Config Parameters](https://user-images.githubusercontent.com/8699212/159517553-7ef67fac-371b-4995-bebe-d702b6167fe1.png)


* `Headings:` headers style.

* `Commands:` commands style.

* `CmdShortDescr:` short description of commands style.

* `ExecName:` executable name style.

* `Flags:` short and long flag names (-f, --flag) style.

* `FlagsDataType:` style of flags data type.

* `FlagsDescr:` flags description text style.

* `Aliases:` list of command aliases style.

* `Example:` example text style.

* `NoExtraNewlines:` no line breaks before and after headings, if `true`. By default: `false`.

* `NoBottomNewline:` no line break at the end of Cobra's output, if `true`. By default: `false`.

<br>

### `NoExtraNewlines` parameter results:

![extranewlines](https://user-images.githubusercontent.com/8699212/159517630-00855ffe-80df-4670-a054-e695f6c4fea7.png)


## How it works

`ColoredCobra` patches Cobra's usage template and extends it with functions for text styling. [fatih/color](https://github.com/fatih/color) library is used for coloring text output in console.

## License

ColoredCobra is released under the MIT license. See [LICENSE](https://github.com/ivanpirog/coloredcobra/blob/main/LICENSE).
