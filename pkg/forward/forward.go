// Package forward implements forwarding SSH sessions to upstream servers.
package forward

import (
	"context"
	"errors"
	"io"
	"sync"

	"go.htdvisser.nl/ssh-gateway/pkg/encoding"
	"go.htdvisser.nl/ssh-gateway/pkg/log"
	"go.htdvisser.nl/ssh-gateway/pkg/recorder"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

var (
	errTargetMissing       = errors.New("target SSH Client missing")
	errRequestsChanMissing = errors.New("requests chan missing")
	errChannelsChanMissing = errors.New("channels chan missing")
)

// Requests forwards ssh requests
func Requests(ctx context.Context, target *ssh.Client, requests <-chan *ssh.Request) error {
	if target == nil {
		return errTargetMissing
	}
	if requests == nil {
		return errRequestsChanMissing
	}
	return forwardClientRequests(ctx, target, requests)
}

func forwardClientRequests(ctx context.Context, target *ssh.Client, requests <-chan *ssh.Request) error {
	for req := range requests {
		ok, payload, err := target.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			return err
		}
		if req.WantReply {
			if err := req.Reply(ok, payload); err != nil {
				return err
			}
		}
		log.FromContext(ctx).Debug("Forward ssh request", zap.String("type", req.Type), zap.Bool("result", ok))
	}
	return nil
}

type channel struct {
	ctx            context.Context
	sourceChannel  ssh.Channel
	targetChannel  ssh.Channel
	sourceRequests <-chan *ssh.Request
	targetRequests <-chan *ssh.Request
	recorder       *recorder.Recorder
	recorderMu     sync.Mutex
	recorderReady  chan struct{}
}

func (c *channel) setRecorder(rec *recorder.Recorder) {
	c.recorderMu.Lock()
	defer c.recorderMu.Unlock()
	if c.recorder == nil && rec != nil {
		c.recorder = rec
		close(c.recorderReady)
	}
}

func (c *channel) getRecorder() *recorder.Recorder {
	c.recorderMu.Lock()
	defer c.recorderMu.Unlock()
	return c.recorder
}

func (c *channel) handle(ctx context.Context) {
	logger := log.FromContext(ctx)

	logger.Debug("Accept channel")
	defer logger.Debug("Close channel")

	if c.recorder != nil {
		defer c.recorder.Close()
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		c.forwardChannelRequests(ctx, c.sourceChannel, c.targetRequests) // nolint:gas
	}()
	go func() {
		defer wg.Done()
		c.forwardChannelRequests(ctx, c.targetChannel, c.sourceRequests) // nolint:gas
	}()
	go func() {
		defer wg.Done()
		defer c.targetChannel.CloseWrite() // Only close the write, we may still expect a response.
		
		// Wait for recorder to be ready (or timeout)
		select {
		case <-c.recorderReady:
		case <-ctx.Done():
		}
		
		var src io.Reader = c.sourceChannel
		rec := c.getRecorder()
		if rec != nil {
			src = recorder.NewRecordingReader(src, rec)
		}
		io.Copy(c.targetChannel, src) // nolint:gas
	}()
	go func() {
		defer wg.Done()
		defer c.sourceChannel.Close()
		
		// Wait for recorder to be ready (or timeout)
		select {
		case <-c.recorderReady:
		case <-ctx.Done():
		}
		
		var dst io.Writer = c.sourceChannel
		rec := c.getRecorder()
		if rec != nil {
			dst = recorder.NewRecordingWriter(dst, rec)
		}
		io.Copy(dst, c.targetChannel) // nolint:gas
	}()
	wg.Wait()
}

func (c *channel) forwardChannelRequests(ctx context.Context, target ssh.Channel, requests <-chan *ssh.Request) error {
	for req := range requests {
		if req.Type == "shell" || req.Type == "exec" {
			for k, v := range EnvironmentFromContext(ctx) {
				target.SendRequest("env", false, append(encoding.String(k), encoding.String(v)...))
			}
		}
		
		// Handle PTY requests to extract terminal dimensions
		if req.Type == "pty-req" {
			if width, height, ok := parsePtyRequest(req.Payload); ok {
				// Create recorder for this session if not already created
				if c.getRecorder() == nil {
					if rec := createRecorder(ctx, width, height); rec != nil {
						c.setRecorder(rec)
						log.FromContext(ctx).Info("Started session recording", 
							zap.Int("width", width), 
							zap.Int("height", height))
					} else {
						// No recording configured, signal ready anyway
						close(c.recorderReady)
					}
				}
			}
		}
		
		ok, err := target.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			return err
		}
		if req.WantReply {
			if err := req.Reply(ok, nil); err != nil {
				return err
			}
		}
		log.FromContext(ctx).Debug("Forward channel request", zap.String("type", req.Type), zap.Bool("result", ok))
	}
	return nil
}

// parsePtyRequest extracts terminal dimensions from a PTY request payload
func parsePtyRequest(payload []byte) (width, height int, ok bool) {
	// PTY request format: string term, uint32 width, uint32 height, uint32 pixelWidth, uint32 pixelHeight, string modes
	_, rest, ok := encoding.ParseString(payload)
	if !ok {
		return
	}
	var w, h uint32
	w, rest, ok = encoding.ParseUint32(rest)
	if !ok {
		return
	}
	h, _, ok = encoding.ParseUint32(rest)
	if !ok {
		return
	}
	return int(w), int(h), true
}

// createRecorder creates a new recorder if recording is enabled in context
func createRecorder(ctx context.Context, width, height int) *recorder.Recorder {
	recPath := RecordingPathFromContext(ctx)
	if recPath == "" {
		return nil
	}
	
	env := EnvironmentFromContext(ctx)
	rec, err := recorder.New(recPath, width, height, env)
	if err != nil {
		log.FromContext(ctx).Warn("Failed to create session recorder", zap.Error(err))
		return nil
	}
	
	return rec
}

// Channels forwards ssh channels
func Channels(ctx context.Context, target *ssh.Client, channels <-chan ssh.NewChannel) error {
	if target == nil {
		return errTargetMissing
	}
	if channels == nil {
		return errChannelsChanMissing
	}
	return forwardChannels(ctx, target, channels)
}

func forwardChannels(ctx context.Context, target *ssh.Client, channels <-chan ssh.NewChannel) error {
	logger := log.FromContext(ctx)
	var wg sync.WaitGroup
	for newChannel := range channels {
		if ctx.Err() != nil {
			if err := newChannel.Reject(ssh.Prohibited, ctx.Err().Error()); err != nil {
				return err
			}
			return ctx.Err()
		}
		targetChannel, targetRequests, err := target.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
		if err, ok := err.(*ssh.OpenChannelError); ok {
			if err := newChannel.Reject(err.Reason, err.Message); err != nil {
				return err
			}
			return err
		}
		sourceChannel, sourceRequests, err := newChannel.Accept()
		if err != nil {
			logger.Error("Could not accept channel", zap.Error(err))
			continue
		}
		channel := &channel{
			sourceChannel:  sourceChannel,
			sourceRequests: sourceRequests,
			targetChannel:  targetChannel,
			targetRequests: targetRequests,
			recorderReady:  make(chan struct{}),
		}
		wg.Add(1)
		go func(newChannel ssh.NewChannel) {
			channel.handle(log.NewContext(ctx, logger.With(zap.String("type", newChannel.ChannelType()))))
			wg.Done()
		}(newChannel)
	}
	wg.Wait()
	return nil
}
