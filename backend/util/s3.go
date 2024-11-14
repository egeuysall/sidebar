package util

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/jpeg"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/google/uuid"
	"github.com/h2non/filetype"
)

func UploadFileToS3(file []byte) (string, string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Printf("error: %v", err)
		return "", "", err
	}

	client := s3.NewFromConfig(cfg)

	uuid := uuid.New().String()

	fileType, err := filetype.MatchReader(bytes.NewReader(file))
	if err != nil {
		return "", "", err
	}

	filename := fmt.Sprintf("%s.%s", uuid, fileType.Extension)

	// Decoding gives you an Image.
	// If you have an io.Reader already, you can give that to Decode 
	// without reading it into a []byte.
	image, _, err := image.Decode(bytes.NewReader(data))
	// check err

	newImage := resize.Resize(160, 0, original_image, resize.Lanczos3)

	// Encode uses a Writer, use a Buffer if you need the raw []byte
	err = jpeg.Encode(someWriter, newImage, nil)
	// check err

	uploader := manager.NewUploader(client)
	uploadOutput, err := uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(os.Getenv("S3_BUCKET_NAME")),
		Key:    aws.String(filename),
		Body:   bytes.NewReader(file),
	})

	if err != nil {
		return "", "", err
	}

	return filename, uploadOutput.Location, nil
}
