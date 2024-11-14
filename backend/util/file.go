package util

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"

	"github.com/h2non/filetype"
)

func ValidateFile(file multipart.File) ([]byte, error) {
	buf, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	fileType, err := filetype.MatchReader(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}

	if fileType.MIME.Value != "image/jpeg" && fileType.MIME.Value != "image/png" {
		return nil, errors.New("file must be a jpeg or png")
	}

	return buf, nil
}
