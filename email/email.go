package email

import (
	"fmt"
	"net/smtp"
)

// Email configuration
var secrets struct {
	SigningSecret string
	EmailProvider string // "smtp", "resend", "sendgrid", etc.
	FromEmail     string
	FromName      string

	// SMTP Configuration
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string

	// Provider-specific API Keys
	ResendAPIKey   string
	SendGridAPIKey string
}

// EmailProvider interface for different email services
type EmailProvider interface {
	Send(to, subject, htmlBody, textBody string) error
}

// Initialize email provider based on configuration
func getEmailProvider() EmailProvider {
	switch secrets.EmailProvider {
	case "smtp":
		return &SMTPProvider{
			Host:     secrets.SMTPHost,
			Port:     secrets.SMTPPort,
			Username: secrets.SMTPUsername,
			Password: secrets.SMTPPassword,
			From:     secrets.FromEmail,
			FromName: secrets.FromName,
		}
	case "resend":
		return &ResendProvider{
			APIKey:   secrets.ResendAPIKey,
			From:     secrets.FromEmail,
			FromName: secrets.FromName,
		}
	case "sendgrid":
		return &SendGridProvider{
			APIKey:   secrets.SendGridAPIKey,
			From:     secrets.FromEmail,
			FromName: secrets.FromName,
		}
	default:
		// Default to SMTP
		return &SMTPProvider{
			Host:     secrets.SMTPHost,
			Port:     secrets.SMTPPort,
			Username: secrets.SMTPUsername,
			Password: secrets.SMTPPassword,
			From:     secrets.FromEmail,
			FromName: secrets.FromName,
		}
	}
}

// SMTPProvider implements email sending via SMTP (works with Mailtrap, Gmail, etc.)
type SMTPProvider struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	FromName string
}

func (s *SMTPProvider) Send(to, subject, htmlBody, textBody string) error {
	// Create email headers and body
	from := fmt.Sprintf("%s <%s>", s.FromName, s.From)

	// Build email message with MIME for HTML
	message := []byte(
		"From: " + from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: multipart/alternative; boundary=\"boundary123\"\r\n" +
			"\r\n" +
			"--boundary123\r\n" +
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
			"\r\n" +
			textBody + "\r\n" +
			"\r\n" +
			"--boundary123\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
			"\r\n" +
			htmlBody + "\r\n" +
			"\r\n" +
			"--boundary123--",
	)

	// Setup authentication
	auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)

	// Send email
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	err := smtp.SendMail(addr, auth, s.From, []string{to}, message)
	if err != nil {
		return fmt.Errorf("failed to send email via SMTP: %w", err)
	}

	fmt.Printf("Email sent successfully via SMTP to: %s\n", to)
	return nil
}

// ResendProvider implements email sending via Resend API
type ResendProvider struct {
	APIKey   string
	From     string
	FromName string
}

func (r *ResendProvider) Send(to, subject, htmlBody, textBody string) error {
	// Note: You'll need to add the resend package if using this
	// go get github.com/resend/resend-go/v2

	return fmt.Errorf("resend provider not implemented - install github.com/resend/resend-go/v2")

	// Uncomment when package is installed:
	/*
		client := resend.NewClient(r.APIKey)
		params := &resend.SendEmailRequest{
			From:    fmt.Sprintf("%s <%s>", r.FromName, r.From),
			To:      []string{to},
			Subject: subject,
			Html:    htmlBody,
			Text:    textBody,
		}
		sent, err := client.Emails.Send(params)
		if err != nil {
			return fmt.Errorf("failed to send email via Resend: %w", err)
		}
		fmt.Printf("Email sent via Resend! ID: %s\n", sent.Id)
		return nil
	*/
}

// SendGridProvider implements email sending via SendGrid API
type SendGridProvider struct {
	APIKey   string
	From     string
	FromName string
}

func (s *SendGridProvider) Send(to, subject, htmlBody, textBody string) error {
	// Note: You'll need to add the sendgrid package if using this
	// go get github.com/sendgrid/sendgrid-go

	return fmt.Errorf("sendgrid provider not implemented - install github.com/sendgrid/sendgrid-go")

	// Uncomment when package is installed:
	/*
		from := mail.NewEmail(s.FromName, s.From)
		toEmail := mail.NewEmail("", to)
		message := mail.NewSingleEmail(from, subject, toEmail, textBody, htmlBody)
		client := sendgrid.NewSendClient(s.APIKey)
		response, err := client.Send(message)
		if err != nil {
			return fmt.Errorf("failed to send email via SendGrid: %w", err)
		}
		fmt.Printf("Email sent via SendGrid! Status: %d\n", response.StatusCode)
		return nil
	*/
}
