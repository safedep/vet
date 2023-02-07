package ui

import (
	"fmt"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
)

var progressWriter progress.Writer
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

func StartProgressWriter() {
	pw := progress.NewWriter()

	pw.SetTrackerLength(25)
	pw.SetMessageWidth(20)
	pw.SetSortBy(progress.SortByPercentDsc)
	pw.SetStyle(progress.StyleDefault)
	pw.SetTrackerPosition(progress.PositionRight)
	pw.SetUpdateFrequency(time.Millisecond * 100)
	pw.Style().Colors = progress.StyleColorsExample
	pw.Style().Options.PercentFormat = "%4.1f%%"
	pw.Style().Visibility.Pinned = true
	pw.Style().Visibility.ETA = true
	pw.Style().Visibility.Value = true

	progressWriter = pw
	go progressWriter.Render()
}

func StopProgressWriter() {
	if progressWriter != nil {
		progressWriter.Stop()
	}
}

func TrackProgress(message string, total int) any {
	tracker := progress.Tracker{Message: message, Total: int64(total),
		Units: progress.UnitsDefault}

	if progressWriter != nil {
		progressWriter.AppendTracker(&tracker)
	}

	return &tracker
}

func MarkTrackerAsDone(i any) {
	if tracker, ok := i.(*progress.Tracker); ok {
		tracker.MarkAsDone()
	}
}

func IncrementTrackerTotal(i any, count int) {
	if tracker, ok := i.(*progress.Tracker); ok {
		tracker.UpdateTotal(tracker.Total + int64(count))
	}
}

func IncrementProgress(i any, count int) {
	if tracker, ok := i.(*progress.Tracker); ok {
		tracker.Increment(int64(count))
	}
}
