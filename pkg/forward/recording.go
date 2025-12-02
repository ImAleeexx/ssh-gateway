package forward

import (
	"context"

	"go.htdvisser.nl/ssh-gateway/pkg/recorder"
)

type recorderKeyType struct{}
type recordingPathKeyType struct{}

var recorderKey recorderKeyType
var recordingPathKey recordingPathKeyType

// NewContextWithRecorder returns a context with the recorder
func NewContextWithRecorder(ctx context.Context, rec *recorder.Recorder) context.Context {
	return context.WithValue(ctx, recorderKey, rec)
}

// RecorderFromContext returns the recorder from the context.
func RecorderFromContext(ctx context.Context) *recorder.Recorder {
	rec, ok := ctx.Value(recorderKey).(*recorder.Recorder)
	if !ok {
		return nil
	}
	return rec
}

// NewContextWithRecordingPath returns a context with the recording path
func NewContextWithRecordingPath(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, recordingPathKey, path)
}

// RecordingPathFromContext returns the recording path from the context.
func RecordingPathFromContext(ctx context.Context) string {
	path, ok := ctx.Value(recordingPathKey).(string)
	if !ok {
		return ""
	}
	return path
}
