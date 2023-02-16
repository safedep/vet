package ui

import (
	"fmt"
	"os"
)

func PrintBanner(s string) {
	fmt.Fprintf(os.Stderr, s)
}
