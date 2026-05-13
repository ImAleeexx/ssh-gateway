package discord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"text/template"
	"time"

	"go.uber.org/zap"
)

type Notifier struct {
	URL          string
	Username     string
	AvatarURL    string
	TextTemplate *template.Template
	Debounce     time.Duration
	Logger       *zap.Logger

	mu               sync.Mutex
	nextEvents       []eventData
	nextNotification *time.Timer
}

var defaultTemplate = template.Must(template.New("default").Parse("{{ range .Events }}`{{ .User }}` connected to `{{ .Upstream }}` from `{{ .RemoteIP }}`{{ with .RemoteIPDesc }} ({{ . }}){{ end }}\n{{ end }}"))

func (n *Notifier) buildMessage(data messageData) (*message, error) {
	msg := message{
		Username:  n.Username,
		AvatarURL: n.AvatarURL,
	}
	template := n.TextTemplate
	if template == nil {
		template = defaultTemplate
	}
	var buf bytes.Buffer
	if err := template.Execute(&buf, data); err != nil {
		return nil, err
	}
	msg.Content = buf.String()
	return &msg, nil
}

type eventData struct {
	User         string
	RemoteIP     string
	RemoteIPDesc string
	Upstream     string
}

type messageData struct {
	Events []eventData
}

type message struct {
	Content   string `json:"content,omitempty"`
	Username  string `json:"username,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

func (n *Notifier) flush(events []eventData) error {
	if len(events) == 0 {
		return nil
	}
	var uniqueEvents []eventData
	seenEvents := make(map[eventData]struct{})
	for _, event := range events {
		if _, seen := seenEvents[event]; seen {
			continue
		}
		uniqueEvents = append(uniqueEvents, event)
		seenEvents[event] = struct{}{}
	}
	msg, err := n.buildMessage(messageData{
		Events: uniqueEvents,
	})
	if err != nil {
		return err
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	res, err := http.Post(n.URL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned HTTP %d", res.StatusCode)
	}
	return nil
}

func (n *Notifier) NotifyConnect(user, remoteIP, remoteIPDesc, upstream string) error {
	if n == nil || n.URL == "" {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nextEvents = append(n.nextEvents, eventData{
		User:         user,
		RemoteIP:     remoteIP,
		RemoteIPDesc: remoteIPDesc,
		Upstream:     upstream,
	})
	debounce := n.Debounce
	if debounce == 0 {
		debounce = time.Minute
	}
	if n.nextNotification == nil {
		n.nextNotification = time.AfterFunc(debounce, func() {
			n.mu.Lock()
			events := n.nextEvents
			n.nextEvents = nil
			n.nextNotification = nil
			n.mu.Unlock()
			if err := n.flush(events); err != nil && n.Logger != nil {
				n.Logger.Error("Failed to send Discord notification", zap.Error(err))
			}
		})
	}
	return nil
}
