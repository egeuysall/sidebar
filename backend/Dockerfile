FROM golang:latest

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o bin/go

EXPOSE 8000

# CMD ["./main"] 

CMD ["./bin/go"]
