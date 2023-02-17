package ui

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/text"
)

func PrintBanner(s string) {
	fmt.Fprintf(os.Stderr, s)
}

func PrintError(s string, args ...any) {
	msg := fmt.Sprintf(s, args...)
	fmt.Fprint(os.Stderr, text.FgRed.Sprint(msg), "\n")
}
