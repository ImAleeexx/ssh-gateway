// Package forward implements forwarding SSH sessions to upstream servers.
package forward

import (
	"context"
	"errors"
	"io"
	"sync"

	"go.htdvisser.nl/ssh-gateway/pkg/encoding"
	"go.htdvisser.nl/ssh-gateway/pkg/log"
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
	sourceChannel  ssh.Channel
	targetChannel  ssh.Channel
	sourceRequests <-chan *ssh.Request
	targetRequests <-chan *ssh.Request

	// sourceRequestMu is held while a request from the source is forwarded and
	// replied to, so that the source channel is not closed before the reply.
	sourceRequestMu sync.Mutex
}

func (c *channel) handle(ctx context.Context) {
	logger := log.FromContext(ctx)

	logger.Debug("Accept channel")
	defer logger.Debug("Close channel")

	// targetDone is done when everything the target sends (stdout, stderr and
	// requests such as "exit-status") has been forwarded to the source. Only
	// then the source channel is closed, otherwise the exit status may be lost.
	var targetDone sync.WaitGroup
	targetDone.Add(3)

	var wg sync.WaitGroup
	wg.Add(6)
	go func() {
		defer wg.Done()
		defer targetDone.Done()
		c.forwardChannelRequests(ctx, c.sourceChannel, c.targetRequests, nil) // nolint:gas
	}()
	go func() {
		defer wg.Done()
		c.forwardChannelRequests(ctx, c.targetChannel, c.sourceRequests, &c.sourceRequestMu) // nolint:gas
		// The source channel is closed, so the target channel is no longer needed.
		c.targetChannel.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(c.targetChannel, c.sourceChannel) // nolint:gas
		c.targetChannel.CloseWrite()              // Only close the write, we may still expect a response.
	}()
	go func() {
		defer wg.Done()
		io.Copy(c.targetChannel.Stderr(), c.sourceChannel.Stderr()) // nolint:gas
	}()
	go func() {
		defer wg.Done()
		defer targetDone.Done()
		io.Copy(c.sourceChannel, c.targetChannel) // nolint:gas
	}()
	go func() {
		defer wg.Done()
		defer targetDone.Done()
		io.Copy(c.sourceChannel.Stderr(), c.targetChannel.Stderr()) // nolint:gas
	}()
	targetDone.Wait()
	c.sourceRequestMu.Lock()
	c.sourceChannel.CloseWrite()
	c.sourceChannel.Close()
	c.sourceRequestMu.Unlock()
	wg.Wait()
}

func (c *channel) forwardChannelRequests(ctx context.Context, target ssh.Channel, requests <-chan *ssh.Request, mu *sync.Mutex) error {
	for req := range requests {
		if err := c.forwardChannelRequest(ctx, target, req, mu); err != nil {
			return err
		}
	}
	return nil
}

func (c *channel) forwardChannelRequest(ctx context.Context, target ssh.Channel, req *ssh.Request, mu *sync.Mutex) error {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	if req.Type == "shell" || req.Type == "exec" {
		for k, v := range EnvironmentFromContext(ctx) {
			target.SendRequest("env", false, append(encoding.String(k), encoding.String(v)...))
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
	return nil
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
		if err != nil {
			// A rejected channel (for example a denied port forward) must not
			// stop forwarding of other channels on the same connection.
			reason, message := ssh.ConnectionFailed, "could not open channel on upstream"
			var openErr *ssh.OpenChannelError
			if errors.As(err, &openErr) {
				reason, message = openErr.Reason, openErr.Message
			} else {
				logger.Warn("Could not open channel on upstream", zap.String("type", newChannel.ChannelType()), zap.Error(err))
			}
			if err := newChannel.Reject(reason, message); err != nil {
				return err
			}
			continue
		}
		sourceChannel, sourceRequests, err := newChannel.Accept()
		if err != nil {
			logger.Error("Could not accept channel", zap.Error(err))
			targetChannel.Close()
			continue
		}
		channel := &channel{
			sourceChannel:  sourceChannel,
			sourceRequests: sourceRequests,
			targetChannel:  targetChannel,
			targetRequests: targetRequests,
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
