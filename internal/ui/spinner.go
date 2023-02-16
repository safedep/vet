package ui

import (
	"fmt"
	"time"
)

var spinnerChan chan bool

func StartSpinner(msg string) {
	style := `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`
	frames := []rune(style)
	length := len(frames)

	spinnerChan = make(chan bool)

	ticker := time.NewTicker(100 * time.Millisecond)
	go func() {
		pos := 0

		for {
			select {
			case <-spinnerChan:
				ticker.Stop()
				return
			case <-ticker.C:
				fmt.Printf("\r%s ... %s", msg, string(frames[pos%length]))
				pos += 1
			}
		}
	}()
}

func StopSpinner() {
	spinnerChan <- true

	fmt.Printf("\r")
	fmt.Println()
}
