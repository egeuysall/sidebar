package models

type LemonSqueezyPayload struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			Tax                     int     `json:"tax"`
			Total                   int     `json:"total"`
			Status                  string  `json:"status"`
			TaxUSD                  int     `json:"tax_usd"`
			Currency                string  `json:"currency"`
			Refunded                bool    `json:"refunded"`
			StoreID                 int     `json:"store_id"`
			Subtotal                int     `json:"subtotal"`
			TaxName                 string  `json:"tax_name"`
			TaxRate                 int     `json:"tax_rate"`
			SetupFee                int     `json:"setup_fee"`
			TestMode                bool    `json:"test_mode"`
			TotalUSD                int     `json:"total_usd"`
			UserName                string  `json:"user_name"`
			CreatedAt               string  `json:"created_at"`
			Identifier              string  `json:"identifier"`
			UpdatedAt               string  `json:"updated_at"`
			UserEmail               string  `json:"user_email"`
			CustomerID              int     `json:"customer_id"`
			RefundedAt              *string `json:"refunded_at"`
			OrderNumber             int     `json:"order_number"`
			SubtotalUSD             int     `json:"subtotal_usd"`
			CurrencyRate            string  `json:"currency_rate"`
			SetupFeeUSD             int     `json:"setup_fee_usd"`
			TaxFormatted            string  `json:"tax_formatted"`
			TaxInclusive            bool    `json:"tax_inclusive"`
			DiscountTotal           int     `json:"discount_total"`
			RefundedAmount          int     `json:"refunded_amount"`
			TotalFormatted          string  `json:"total_formatted"`
			StatusFormatted         string  `json:"status_formatted"`
			DiscountTotalUSD        int     `json:"discount_total_usd"`
			SubtotalFormatted       string  `json:"subtotal_formatted"`
			RefundedAmountUSD       int     `json:"refunded_amount_usd"`
			SetupFeeFormatted       string  `json:"setup_fee_formatted"`
			DiscountTotalFormatted  string  `json:"discount_total_formatted"`
			RefundedAmountFormatted string  `json:"refunded_amount_formatted"`
			FirstOrderItem          struct {
				ID          int    `json:"id"`
				Price       int    `json:"price"`
				OrderID     int    `json:"order_id"`
				PriceID     int    `json:"price_id"`
				Quantity    int    `json:"quantity"`
				TestMode    bool   `json:"test_mode"`
				CreatedAt   string `json:"created_at"`
				ProductID   int    `json:"product_id"`
				UpdatedAt   string `json:"updated_at"`
				VariantID   int    `json:"variant_id"`
				ProductName string `json:"product_name"`
				VariantName string `json:"variant_name"`
			} `json:"first_order_item"`
		} `json:"attributes"`
	} `json:"data"`
	Meta struct {
		TestMode  bool   `json:"test_mode"`
		EventName string `json:"event_name"`
		WebhookID string `json:"webhook_id"`
	} `json:"meta"`
}

type LemonSqueezyOrderAttributes struct {
	TaxUSD                  int     `json:"tax_usd"`
	Subtotal                int     `json:"subtotal"`
	TotalUSD                int     `json:"total_usd"`
	UserName                string  `json:"user_name"`
	UserEmail               string  `json:"user_email"`
	OrderNumber             int     `json:"order_number"`
	SubtotalUSD             int     `json:"subtotal_usd"`
	DiscountTotal           int     `json:"discount_total"`
	Identifier              string  `json:"identifier"`
	FirstOrderItem          struct {
		ID          int    `json:"id"`
		ProductID   int    `json:"product_id"`
		VariantID   int    `json:"variant_id"`
		ProductName string `json:"product_name"`
		VariantName string `json:"variant_name"`
	} `json:"first_order_item"`
}
