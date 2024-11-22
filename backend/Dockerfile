FROM golang:latest

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o bin/go

EXPOSE 8000

<<<<<<< HEAD
CMD ["./main"] 
=======
CMD ["./bin/go"]
>>>>>>> 0ac58f76861cf6039f0fc0160e2fbb80732f8662
