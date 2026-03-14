package mailer

import (
	"context"
	"fmt"
	"net/smtp"
)

// Email configuration
var secrets struct {
	FromEmail string
	FromName  string
	
	// SMTP Configuration (works with all providers)
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
}

// EmailRequest represents an email to be sent
type EmailRequest struct {
	To      string
	Subject string
	HTML    string
	Text    string
}

// Send sends an email using SMTP
//
//encore:api private
func Send(ctx context.Context, req *EmailRequest) error {
	if req.To == "" {
		return fmt.Errorf("recipient email is required")
	}
	if req.Subject == "" {
		return fmt.Errorf("email subject is required")
	}
	if req.HTML == "" && req.Text == "" {
		return fmt.Errorf("email must have either HTML or text content")
	}
	
	return sendViaSMTP(req)
}

// SendTemplateRequest sends a templated email (for common use cases)
type SendTemplateRequest struct {
	To           string
	TemplateName string
	Data         map[string]string
}

//encore:api private
func SendTemplate(ctx context.Context, req *SendTemplateRequest) error {
	template, err := getTemplate(req.TemplateName, req.Data)
	if err != nil {
		return fmt.Errorf("failed to get template: %w", err)
	}
	
	return Send(ctx, &EmailRequest{
		To:      req.To,
		Subject: template.Subject,
		HTML:    template.HTML,
		Text:    template.Text,
	})
}

// EmailTemplate struct
type EmailTemplate struct {
	Subject string
	HTML    string
	Text    string
}

func getTemplate(name string, data map[string]string) (*EmailTemplate, error) {
	switch name {
	case "verification":
		return &EmailTemplate{
			Subject: "Verify Your Email Address",
			HTML:    buildVerificationHTML(data),
			Text:    buildVerificationText(data),
		}, nil
	case "password-reset":
		return &EmailTemplate{
			Subject: "Reset Your Password",
			HTML:    buildPasswordResetHTML(data),
			Text:    buildPasswordResetText(data),
		}, nil
	case "welcome":
		return &EmailTemplate{
			Subject: "Welcome to " + secrets.FromName,
			HTML:    buildWelcomeHTML(data),
			Text:    buildWelcomeText(data),
		}, nil
	default:
		return nil, fmt.Errorf("unknown template: %s", name)
	}
}

func buildVerificationHTML(data map[string]string) string {
	name := data["name"]
	url := data["url"]
	
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f8f9fa; border-radius: 10px; padding: 30px; margin-bottom: 20px;">
        <h1 style="color: #2c3e50; margin-bottom: 20px;">Verify Your Email Address</h1>
        <p style="font-size: 16px; margin-bottom: 20px;">Hi %s,</p>
        <p style="font-size: 16px; margin-bottom: 20px;">
            Thank you for registering! Please verify your email address by clicking the button below:
        </p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="%s"
               style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Verify Email Address
            </a>
        </div>
        <p style="font-size: 14px; color: #666; margin-top: 30px;">
            Or copy and paste this link into your browser:<br>
            <a href="%s" style="color: #007bff; word-break: break-all;">%s</a>
        </p>
        <p style="font-size: 14px; color: #666; margin-top: 20px;">
            This link will expire in 24 hours.
        </p>
        <p style="font-size: 14px; color: #666; margin-top: 20px;">
            If you didn't create an account, please ignore this email.
        </p>
    </div>
    <div style="text-align: center; color: #999; font-size: 12px;">
        <p>© 2024 %s. All rights reserved.</p>
    </div>
</body>
</html>
`, name, url, url, url, secrets.FromName)
}

func buildVerificationText(data map[string]string) string {
	name := data["name"]
	url := data["url"]
	
	return fmt.Sprintf(`
Hi %s,

Thank you for registering! Please verify your email address by clicking the link below:

%s

This link will expire in 24 hours.

If you didn't create an account, please ignore this email.

Best regards,
%s
`, name, url, secrets.FromName)
}

func buildPasswordResetHTML(data map[string]string) string {
	name := data["name"]
	url := data["url"]
	
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f8f9fa; border-radius: 10px; padding: 30px; margin-bottom: 20px;">
        <h1 style="color: #2c3e50; margin-bottom: 20px;">Reset Your Password</h1>
        <p style="font-size: 16px; margin-bottom: 20px;">Hi %s,</p>
        <p style="font-size: 16px; margin-bottom: 20px;">
            We received a request to reset your password. Click the button below to create a new password:
        </p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="%s"
               style="background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">
                Reset Password
            </a>
        </div>
        <p style="font-size: 14px; color: #666; margin-top: 30px;">
            Or copy and paste this link into your browser:<br>
            <a href="%s" style="color: #dc3545; word-break: break-all;">%s</a>
        </p>
        <p style="font-size: 14px; color: #666; margin-top: 20px;">
            This link will expire in 1 hour.
        </p>
        <p style="font-size: 14px; color: #666; margin-top: 20px;">
            If you didn't request a password reset, please ignore this email or contact support if you have concerns.
        </p>
    </div>
    <div style="text-align: center; color: #999; font-size: 12px;">
        <p>© 2024 %s. All rights reserved.</p>
    </div>
</body>
</html>
`, name, url, url, url, secrets.FromName)
}

func buildPasswordResetText(data map[string]string) string {
	name := data["name"]
	url := data["url"]
	
	return fmt.Sprintf(`
Hi %s,

We received a request to reset your password. Click the link below to create a new password:

%s

This link will expire in 1 hour.

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

Best regards,
%s
`, name, url, secrets.FromName)
}

func buildWelcomeHTML(data map[string]string) string {
	name := data["name"]
	
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background-color: #f8f9fa; border-radius: 10px; padding: 30px; margin-bottom: 20px;">
        <h1 style="color: #2c3e50; margin-bottom: 20px;">Welcome to %s! 🎉</h1>
        <p style="font-size: 16px; margin-bottom: 20px;">Hi %s,</p>
        <p style="font-size: 16px; margin-bottom: 20px;">
            Thank you for verifying your email! Your account is now fully activated.
        </p>
        <p style="font-size: 16px; margin-bottom: 20px;">
            We're excited to have you on board. If you have any questions, feel free to reach out to our support team.
        </p>
        <p style="font-size: 16px; margin-bottom: 20px;">
            Happy exploring!
        </p>
    </div>
    <div style="text-align: center; color: #999; font-size: 12px;">
        <p>© 2024 %s. All rights reserved.</p>
    </div>
</body>
</html>
`, secrets.FromName, name, secrets.FromName)
}

func buildWelcomeText(data map[string]string) string {
	name := data["name"]
	
	return fmt.Sprintf(`
Hi %s,

Thank you for verifying your email! Your account is now fully activated.

We're excited to have you on board. If you have any questions, feel free to reach out to our support team.

Happy exploring!

Best regards,
%s
`, name, secrets.FromName)
}

// sendViaSMTP sends email via SMTP
func sendViaSMTP(req *EmailRequest) error {
	from := fmt.Sprintf("%s <%s>", secrets.FromName, secrets.FromEmail)
	
	// Build email message with MIME for HTML
	message := []byte(
		"From: " + from + "\r\n" +
			"To: " + req.To + "\r\n" +
			"Subject: " + req.Subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: multipart/alternative; boundary=\"boundary123\"\r\n" +
			"\r\n" +
			"--boundary123\r\n" +
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n" +
			"\r\n" +
			req.Text + "\r\n" +
			"\r\n" +
			"--boundary123\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
			"\r\n" +
			req.HTML + "\r\n" +
			"\r\n" +
			"--boundary123--",
	)
	
	auth := smtp.PlainAuth("", secrets.SMTPUsername, secrets.SMTPPassword, secrets.SMTPHost)
	addr := fmt.Sprintf("%s:%d", secrets.SMTPHost, secrets.SMTPPort)
	
	err := smtp.SendMail(addr, auth, secrets.FromEmail, []string{req.To}, message)
	if err != nil {
		return fmt.Errorf("failed to send email via SMTP: %w", err)
	}
	
	fmt.Printf("Email sent successfully via SMTP to: %s\n", req.To)
	return nil
}
