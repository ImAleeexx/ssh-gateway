// Package cmd implements dispatching commands on the SSH gateway using SSH's
// "exec" requests.
package cmd

import (
	"context"
	"fmt"
	"io"

	"go.htdvisser.nl/ssh-gateway/pkg/encoding"
	"go.htdvisser.nl/ssh-gateway/pkg/log"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// Command is the function signature of a command. It has access to the permissions
// of the connected user, the environment set by the connected user, and it can
// read/write to the channel.
type Command func(ctx context.Context, conn *ssh.Permissions, env map[string]string, rw io.ReadWriter) error

// Dispatcher is a collection of named commands.
type Dispatcher map[string]Command

// Dispatch dispatches commands.
func (r Dispatcher) Dispatch(ctx context.Context, sshConn *ssh.ServerConn, sshChannels <-chan ssh.NewChannel, sshRequests <-chan *ssh.Request) error {
	logger := log.FromContext(ctx)
	go ssh.DiscardRequests(sshRequests)
	for newChannel := range sshChannels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			logger.Warn("Could not accept channel", zap.Error(err))
			return err
		}
		// Commands do not read input. Discard it, so that the client is not
		// blocked by flow control and untrusted input never reaches the logs.
		go io.Copy(io.Discard, channel) // nolint:gas
		env := make(map[string]string)
		for req := range channelRequests {
			switch req.Type {
			case "pty-req":
				req.Reply(true, nil)
			case "shell":
				req.Reply(true, nil)
				fmt.Fprint(channel, "No shell available.\r\n")
				channel.SendRequest("exit-status", false, encoding.Uint32(1))
				channel.Close()
			case "env":
				k, rest, ok := encoding.ParseString(req.Payload)
				if !ok {
					req.Reply(false, nil)
					continue
				}
				v, rest, ok := encoding.ParseString(rest)
				if !ok || len(rest) != 0 {
					req.Reply(false, nil)
					continue
				}
				env[k] = v
				req.Reply(true, nil)
			case "exec":
				cmdName, rest, ok := encoding.ParseString(req.Payload)
				if !ok || len(rest) != 0 {
					req.Reply(false, nil)
					continue
				}
				cmdLogger := logger.With(zap.String("command", cmdName))
				cmd, ok := r[cmdName]
				req.Reply(ok, nil)
				if !ok {
					cmdLogger.Warn("Unknown command")
					fmt.Fprintf(channel, "Unknown command.\r\n")
					channel.SendRequest("exit-status", false, encoding.Uint32(127))
					channel.Close()
					continue
				}
				cmdLogger.Debug("Dispatching command")
				err := cmd(ctx, sshConn.Permissions, env, channel)
				if err == nil {
					cmdLogger.Info("Executed command")
					channel.SendRequest("exit-status", false, encoding.Uint32(0))
				} else {
					cmdLogger.Warn("Executed command", zap.Error(err))
					channel.SendRequest("exit-status", false, encoding.Uint32(1))
				}
				channel.Close()
			default:
				logger.Warn(
					"unknown channel request",
					zap.String("request_type", req.Type),
					zap.Bool("want_reply", req.WantReply),
				)
				req.Reply(false, nil)
			}
		}
	}
	return nil
}
