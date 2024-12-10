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

	toAddress := to

	if os.Getenv("ENVIRONMENT") == "development" {
		toAddress = os.Getenv("TEST_DELIVERED_EMAIL")
	}

	params := &resend.SendEmailRequest{
		From:    fromAddress,
		To:      []string{toAddress},
		Subject: subject,
		Html:    html,
	}

	_, err := client.Emails.Send(params)
	return err
}
