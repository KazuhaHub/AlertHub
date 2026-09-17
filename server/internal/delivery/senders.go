package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/KazuhaHub/AlertHub/server/internal/alert"
)

// WebhookSender POSTs the signed alert envelope to each configured URL (all
// severities). One durable job per URL.
type WebhookSender struct {
	URLs   []string
	client *http.Client
}

func NewWebhookSender(urls []string) *WebhookSender {
	return &WebhookSender{URLs: urls, client: &http.Client{Timeout: 8 * time.Second}}
}

func (w *WebhookSender) Channel() string                 { return "webhook" }
func (w *WebhookSender) Targets(a *alert.Alert) []string { return w.URLs }

func (w *WebhookSender) Send(ctx context.Context, target, payload string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AlertHub")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// EmailSender sends SMTP mail for critical/emergency alerts. One durable job per
// recipient (so one bad address can't block the others).
type EmailSender struct {
	Host, Port, User, Pass, From string
	To                           []string
}

func (e *EmailSender) Channel() string { return "email" }

func (e *EmailSender) Targets(a *alert.Alert) []string {
	if e.Host == "" || len(e.To) == 0 {
		return nil
	}
	if a.Severity != "critical" && a.Severity != "emergency" {
		return nil
	}
	return e.To
}

func (e *EmailSender) Send(_ context.Context, target, payload string) error {
	var a alert.Alert
	if err := json.Unmarshal([]byte(payload), &a); err != nil {
		return err
	}
	subject := fmt.Sprintf("[AlertHub %s] %s", strings.ToUpper(a.Severity), a.Title)
	body := a.Body
	if a.Action != "" {
		body += "\r\n\r\n→ " + a.Action
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		e.From, target, subject, body)
	var auth smtp.Auth
	if e.User != "" {
		auth = smtp.PlainAuth("", e.User, e.Pass, e.Host)
	}
	return smtp.SendMail(e.Host+":"+e.Port, auth, e.From, []string{target}, []byte(msg))
}
