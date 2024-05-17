package ui

import (
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/progress"
)

var progressWriter progress.Writer

func StartProgressWriter() {
	pw := progress.NewWriter()

	pw.SetAutoStop(false)
	pw.SetTrackerLength(25)
	pw.SetMessageLength(20)
	pw.SetSortBy(progress.SortByPercentDsc)
	pw.SetStyle(progress.StyleDefault)
	pw.SetOutputWriter(os.Stderr)
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
		time.Sleep(1 * time.Second)
	}
}

func SetPinnedMessageOnProgressWriter(msg string) {
	if progressWriter != nil {
		progressWriter.SetPinnedMessages(msg)
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

func IncrementTrackerTotal(i any, count int64) {
	if tracker, ok := i.(*progress.Tracker); ok {
		tracker.UpdateTotal(tracker.Total + count)
	}
}

func IncrementProgress(i any, count int64) {
	if tracker, ok := i.(*progress.Tracker); ok && (progressTrackerDelta(tracker) > count) {
		tracker.Increment(count)
	}
}

func UpdateValue(i any, count int64) {
	if tracker, ok := i.(*progress.Tracker); ok {
		tracker.SetValue(count)
	}
}

func progressTrackerDelta(tracker *progress.Tracker) int64 {
	return (tracker.Total - tracker.Value())
}
