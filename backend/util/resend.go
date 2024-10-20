package util

import (
	"fmt"
	"os"

	"github.com/resend/resend-go/v2"
)

func SendEmail(to string, subject string, html string) error {
	from := os.Getenv("EMAIL_FROM_ADDRESS")
	fromName := os.Getenv("EMAIL_FROM_NAME")
	apiKey := os.Getenv("RESEND_API_KEY")

	fromAddress := fmt.Sprintf("%s <%s>", fromName, from)

	client := resend.NewClient(apiKey)

	params := &resend.SendEmailRequest{
		From: fromAddress,
		To: []string{to},
		Subject: subject,
		Html: html,
	}

	_, err := client.Emails.Send(params)
	return err
}