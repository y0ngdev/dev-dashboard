package mailer

import (
	"context"
	"errors"
	"fmt"
	"net/smtp"

	"encore.dev/beta/errs"
	"encore.dev/rlog"
)

var secrets struct {
	FromEmail string
	FromName  string

	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
}

// EmailRequest represents an email to be sent.
type EmailRequest struct {
	To      string
	Subject string
	HTML    string
	Text    string
}

// Send sends an email via SMTP.
//
//encore:api private
func Send(_ context.Context, req *EmailRequest) error {
	if req.To == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("recipient email is required").Err()
	}
	if req.Subject == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("email subject is required").Err()
	}
	if req.HTML == "" && req.Text == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("email must have either HTML or text content").Err()
	}

	return sendViaSMTP(req)
}

// SendTemplateRequest sends a named template email.
type SendTemplateRequest struct {
	To           string
	TemplateName string
	Data         map[string]string
}

// SendTemplate resolves a template and sends the email.
//
//encore:api private
func SendTemplate(ctx context.Context, req *SendTemplateRequest) error {
	tmpl, err := getTemplate(req.TemplateName, req.Data)
	if err != nil {
		return errs.B().Cause(err).Code(errs.InvalidArgument).Msgf("template %q not found", req.TemplateName).Err()
	}

	return Send(ctx, &EmailRequest{
		To:      req.To,
		Subject: tmpl.Subject,
		HTML:    tmpl.HTML,
		Text:    tmpl.Text,
	})
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

type emailTemplate struct {
	Subject string
	HTML    string
	Text    string
}

func getTemplate(name string, data map[string]string) (*emailTemplate, error) {
	switch name {
	case "verification":
		return &emailTemplate{
			Subject: "Verify Your Email Address",
			HTML:    buildVerificationHTML(data),
			Text:    buildVerificationText(data),
		}, nil
	case "password-reset":
		return &emailTemplate{
			Subject: "Reset Your Password",
			HTML:    buildPasswordResetHTML(data),
			Text:    buildPasswordResetText(data),
		}, nil
	case "welcome":
		return &emailTemplate{
			Subject: "Welcome to " + secrets.FromName,
			HTML:    buildWelcomeHTML(data),
			Text:    buildWelcomeText(data),
		}, nil
	default:
		return nil, errors.New("unknown template")
	}
}

func buildVerificationHTML(data map[string]string) string {
	name := data["name"]
	url := data["url"]

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family:Arial,sans-serif;line-height:1.6;color:#333;max-width:600px;margin:0 auto;padding:20px;">
  <div style="background:#f8f9fa;border-radius:10px;padding:30px;margin-bottom:20px;">
    <h1 style="color:#2c3e50;margin-bottom:20px;">Verify Your Email Address</h1>
    <p style="font-size:16px;margin-bottom:20px;">Hi %s,</p>
    <p style="font-size:16px;margin-bottom:20px;">
      Thank you for registering! Please verify your email address by clicking the button below:
    </p>
    <div style="text-align:center;margin:30px 0;">
      <a href="%s" style="background:#007bff;color:white;padding:12px 30px;text-decoration:none;border-radius:5px;display:inline-block;font-weight:bold;">
        Verify Email Address
      </a>
    </div>
    <p style="font-size:14px;color:#666;margin-top:30px;">
      Or copy and paste this link:<br>
      <a href="%s" style="color:#007bff;word-break:break-all;">%s</a>
    </p>
    <p style="font-size:14px;color:#666;margin-top:20px;">This link expires in 24 hours.</p>
    <p style="font-size:14px;color:#666;margin-top:20px;">If you did not create an account, you can safely ignore this email.</p>
  </div>
  <div style="text-align:center;color:#999;font-size:12px;">
    <p>&copy; %s. All rights reserved.</p>
  </div>
</body>
</html>`, name, url, url, url, secrets.FromName)
}

func buildVerificationText(data map[string]string) string {
	return fmt.Sprintf("Hi %s,\n\nPlease verify your email address:\n\n%s\n\nThis link expires in 24 hours.\n\nIf you did not create an account, ignore this email.\n\n-- %s",
		data["name"], data["url"], secrets.FromName)
}

func buildPasswordResetHTML(data map[string]string) string {
	name := data["name"]
	url := data["url"]

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family:Arial,sans-serif;line-height:1.6;color:#333;max-width:600px;margin:0 auto;padding:20px;">
  <div style="background:#f8f9fa;border-radius:10px;padding:30px;margin-bottom:20px;">
    <h1 style="color:#2c3e50;margin-bottom:20px;">Reset Your Password</h1>
    <p style="font-size:16px;margin-bottom:20px;">Hi %s,</p>
    <p style="font-size:16px;margin-bottom:20px;">
      We received a request to reset your password. Click the button below:
    </p>
    <div style="text-align:center;margin:30px 0;">
      <a href="%s" style="background:#dc3545;color:white;padding:12px 30px;text-decoration:none;border-radius:5px;display:inline-block;font-weight:bold;">
        Reset Password
      </a>
    </div>
    <p style="font-size:14px;color:#666;margin-top:30px;">
      Or copy and paste this link:<br>
      <a href="%s" style="color:#dc3545;word-break:break-all;">%s</a>
    </p>
    <p style="font-size:14px;color:#666;margin-top:20px;">This link expires in 1 hour.</p>
    <p style="font-size:14px;color:#666;margin-top:20px;">If you did not request a password reset, you can safely ignore this email.</p>
  </div>
  <div style="text-align:center;color:#999;font-size:12px;">
    <p>&copy; %s. All rights reserved.</p>
  </div>
</body>
</html>`, name, url, url, url, secrets.FromName)
}

func buildPasswordResetText(data map[string]string) string {
	return fmt.Sprintf("Hi %s,\n\nReset your password:\n\n%s\n\nThis link expires in 1 hour.\n\nIf you did not request this, ignore this email.\n\n-- %s",
		data["name"], data["url"], secrets.FromName)
}

func buildWelcomeHTML(data map[string]string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family:Arial,sans-serif;line-height:1.6;color:#333;max-width:600px;margin:0 auto;padding:20px;">
  <div style="background:#f8f9fa;border-radius:10px;padding:30px;margin-bottom:20px;">
    <h1 style="color:#2c3e50;margin-bottom:20px;">Welcome to %s!</h1>
    <p style="font-size:16px;margin-bottom:20px;">Hi %s,</p>
    <p style="font-size:16px;margin-bottom:20px;">
      Your email has been verified and your account is now fully active.
    </p>
    <p style="font-size:16px;margin-bottom:20px;">
      We are excited to have you on board. If you have any questions, reach out to our support team.
    </p>
  </div>
  <div style="text-align:center;color:#999;font-size:12px;">
    <p>&copy; %s. All rights reserved.</p>
  </div>
</body>
</html>`, secrets.FromName, data["name"], secrets.FromName)
}

func buildWelcomeText(data map[string]string) string {
	return fmt.Sprintf("Hi %s,\n\nYour email has been verified and your account is now active.\n\nWelcome aboard!\n\n-- %s",
		data["name"], secrets.FromName)
}

// ---------------------------------------------------------------------------
// SMTP transport
// ---------------------------------------------------------------------------

func sendViaSMTP(req *EmailRequest) error {
	from := fmt.Sprintf("%s <%s>", secrets.FromName, secrets.FromEmail)
	addr := fmt.Sprintf("%s:%s", secrets.SMTPHost, secrets.SMTPPort)

	const boundary = "==MIMEBoundary=="
	message := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n--%s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n\r\n--%s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n\r\n--%s--",
		from, req.To, req.Subject,
		boundary, boundary, req.Text,
		boundary, req.HTML,
		boundary,
	)

	smtpAuth := smtp.PlainAuth("", secrets.SMTPUsername, secrets.SMTPPassword, secrets.SMTPHost)
	if err := smtp.SendMail(addr, smtpAuth, secrets.FromEmail, []string{req.To}, []byte(message)); err != nil {
		return errs.B().Cause(err).Code(errs.Internal).Msg("SMTP send failed").Err()
	}

	rlog.Info("email sent", "to", req.To, "subject", req.Subject)
	return nil
}
