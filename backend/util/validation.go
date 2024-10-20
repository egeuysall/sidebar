package util

import "unicode"

func ValidatePassword(password string) (eightOrMore, number, upper, special bool) {
	letters := 0
	for _, char := range password {
		switch {
		case unicode.IsNumber(char):
			number = true
			letters++
		case unicode.IsUpper(char):
			upper = true
			letters++
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			special = true
		case unicode.IsLetter(char) || char == ' ':
			letters++
		default:
            //return false, false, false, false
        }
    }
	eightOrMore = letters >= 8
	return
}
