package ui

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/text"
)

func PrintBanner(s string) {
	fmt.Fprintf(os.Stderr, s)
}

func PrintSuccess(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprint(os.Stderr, text.FgGreen.Sprint(msg), "\n")
}

func PrintMsg(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprint(os.Stderr, text.Bold.Sprint(msg), "\n")
}

func PrintWarning(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprint(os.Stdout, text.FgYellow.Sprint(msg), "\n")
}

func PrintError(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprint(os.Stderr, text.FgRed.Sprint(msg), "\n")
}
