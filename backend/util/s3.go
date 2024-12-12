package util

import (
	"bytes"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/google/uuid"
	"github.com/h2non/filetype"
	"github.com/nfnt/resize"
	"image"
	"image/jpeg"
	"image/png"
	"os"
)

func UploadFileToS3(file []byte) (string, string, error) {
	// aws config
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(os.Getenv("AWS_REGION")),
	)
	if err != nil {
		return "", "", fmt.Errorf("aws config error: %v", err)
	}

	// generate unique filename
	key := uuid.New().String()
	fileType, err := filetype.MatchReader(bytes.NewReader(file))
	if err != nil {
		return "", "", fmt.Errorf("file type detection error: %v", err)
	}
	filename := fmt.Sprintf("%s.%s", key, fileType.Extension)

	// create thumbnail
	img, format, err := image.Decode(bytes.NewReader(file))
	if err != nil {
		return "", "", fmt.Errorf("image decode error: %v", err)
	}

	// use buffered writer for thumbnail
	var thumbnailBuf bytes.Buffer
	thumbnail := resize.Resize(160, 0, img, resize.Lanczos3)

	// encode based on original format
	switch format {
	case "jpeg", "jpg":
		err = jpeg.Encode(&thumbnailBuf, thumbnail, nil)
	case "png":
		err = png.Encode(&thumbnailBuf, thumbnail)
	default:
		return "", "", fmt.Errorf("unsupported image format: %s", format)
	}
	if err != nil {
		return "", "", fmt.Errorf("thumbnail encode error: %v", err)
	}

	// upload original and thumbnail
	client := s3.NewFromConfig(cfg)
	uploader := manager.NewUploader(client)

	// upload original
	uploadOutput, err := uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(os.Getenv("S3_BUCKET_NAME")),
		Key:    aws.String(filename),
		Body:   bytes.NewReader(file),
	})
	if err != nil {
		return "", "", fmt.Errorf("original file upload error: %v", err)
	}

	// upload thumbnail with _thumb suffix
	thumbnailKey := fmt.Sprintf("%s_thumb.%s", key, fileType.Extension)
	_, err = uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(os.Getenv("S3_BUCKET_NAME")),
		Key:    aws.String(thumbnailKey),
		Body:   bytes.NewReader(thumbnailBuf.Bytes()),
	})
	if err != nil {
		return "", "", fmt.Errorf("thumbnail upload error: %v", err)
	}

	return filename, uploadOutput.Location, nil
}
