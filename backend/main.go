package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/colecaccamise/go-backend/api"
	"github.com/colecaccamise/go-backend/storage"
	"github.com/joho/godotenv"
)

func main() {
	fmt.Println("Starting server...")

	listenAddr := flag.String("listenAddr", ":8000", "The server address to listen on.")
	flag.Parse()

	err := godotenv.Load()
	environment := os.Getenv("ENVIRONMENT")
	if err != nil && environment != "production" {
		log.Fatalf("Error loading .env file")
	}

	store, err := storage.NewPostgresStore()
	if err != nil {
		log.Fatalf("Error creating postgres store: %s", err.Error())
	}

	err = store.Init()
	if err != nil {
		log.Fatalf("Error initializing postgres store: %s", err.Error())
	}

	server := api.NewServer(*listenAddr, store)

	log.Fatal(server.Start())
}
