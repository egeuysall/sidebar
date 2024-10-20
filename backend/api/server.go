package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/colecaccamise/go-backend/middleware"
	"github.com/colecaccamise/go-backend/models"
	"github.com/colecaccamise/go-backend/storage"
	"github.com/colecaccamise/go-backend/util"
	"github.com/go-chi/chi"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/cors"
	"github.com/stripe/stripe-go/v80"
	"golang.org/x/crypto/bcrypt"
)

type ApiError struct {
	Message string `json:"message"`
	Error string `json:"error"`
}

type apiFunc func(http.ResponseWriter, *http.Request) error

type Server struct {
	listenAddr string
	store      storage.Storage
}

func NewServer(listenAddr string, store storage.Storage) *Server {
	return &Server{
		listenAddr: listenAddr,
		store: store,
	}
}

func (s *Server) Start() error {
	r := chi.NewRouter()

	stripe.Key = os.Getenv("STRIPE_KEY")

	r.NotFound(makeHttpHandleFunc(handleNotFound))
	r.MethodNotAllowed(makeHttpHandleFunc(handleMethodNotAllowed))

	r.Route("/auth", func(r chi.Router) {
		r.Post("/signup", makeHttpHandleFunc(s.handleSignup))
		r.Post("/login", makeHttpHandleFunc(s.handleLogin))
		r.Post("/confirm", makeHttpHandleFunc(s.handleConfirmEmailToken))
	})

	r.Route("/webhooks", func(r chi.Router) {
		r.Post("/lemonsqueezy", makeHttpHandleFunc(s.handleLemonSqueezyWebhook))
	})

	r.Group(func(r chi.Router) {
		r.Use(middleware.VerifyAuth)
		r.Post("/users", makeHttpHandleFunc(s.handleCreateUser))
		r.Get("/users", makeHttpHandleFunc(s.handleGetAllUsers))
		r.Get("/users/{id}", makeHttpHandleFunc(s.handleGetUserByID))
		r.Delete("/users/{id}", makeHttpHandleFunc(s.handleDeleteUserByID))
	})

	stack := middleware.CreateStack(
		middleware.Logging,
		middleware.Nosniff,
	)

	fmt.Println("Server is running on port", s.listenAddr)

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:3000", "http://localhost:8000", "https://colecaccamise.com"},
		AllowCredentials: true,
		AllowedMethods: []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		ExposedHeaders: []string{"Content-Type", "Location"},
		AllowOriginFunc:  func(origin string) bool { 
			if os.Getenv("ENVIRONMENT") == "development" {
				return origin == "http://localhost:3000" || origin == "http://localhost:8000"
			} else {
				return origin == "https://colecaccamise.com"
			}
		},
		// Enable Debugging for testing, disable in production
		Debug: os.Getenv("ENVIRONMENT") == "development",
	})

	handler := c.Handler(stack(r))

	return http.ListenAndServe(s.listenAddr, handler)
}

func handleNotFound(w http.ResponseWriter, req *http.Request) error {
	return WriteJSON(w, http.StatusNotFound, ApiError{Message: fmt.Sprintf("cannot %s %s", req.Method, req.URL.Path), Error: "route not found"})
}

func handleMethodNotAllowed(w http.ResponseWriter, req *http.Request) error {
	return WriteJSON(w, http.StatusMethodNotAllowed, ApiError{Message: fmt.Sprintf("cannot %s %s", req.Method, req.URL.Path), Error: "method not allowed"})
}

func (s *Server) handleLemonSqueezyWebhook(w http.ResponseWriter, r *http.Request) error {
	receivedSignature := r.Header.Get("X-Signature")

	if receivedSignature == "" {
		return WriteJSON(w, http.StatusUnauthorized, ApiError{Message: "invalid signature", Error: "Unauthorized"})
	} else {
		fmt.Printf("received signature: %s\n", receivedSignature)
	}

	payload := new(models.LemonSqueezyPayload)
	err := json.NewDecoder(r.Body).Decode(payload)

	switch {
	case err == io.EOF:
		return WriteJSON(w, http.StatusBadRequest, ApiError{Message: "invalid request", Error: "empty body"})
	case err != nil:
		return WriteJSON(w, http.StatusBadRequest, ApiError{Message: "invalid request", Error: err.Error()})
	}

	event := payload.Meta.EventName

	attributes := payload.Data.Attributes
	order := &models.LemonSqueezyOrderAttributes{
		OrderNumber:     attributes.OrderNumber,
		UserName:        attributes.UserName,
		UserEmail:       attributes.UserEmail,
		SubtotalUSD:     attributes.SubtotalUSD,
		TotalUSD:        attributes.TotalUSD,
		Identifier:      attributes.Identifier,
		FirstOrderItem: struct {
			ID          int    `json:"id"`
			ProductID   int    `json:"product_id"`
			VariantID   int    `json:"variant_id"`
			ProductName string `json:"product_name"`
			VariantName string `json:"variant_name"`
		}{
			ID:          attributes.FirstOrderItem.ID,
			ProductID:   attributes.FirstOrderItem.ProductID,
			VariantID:   attributes.FirstOrderItem.VariantID,
			ProductName: attributes.FirstOrderItem.ProductName,
			VariantName: attributes.FirstOrderItem.VariantName,
		},
	}

	switch event {
	case "order_created":
		orderNumber := strconv.Itoa(order.OrderNumber)
		subtotal := fmt.Sprintf("%.2f", float64(order.SubtotalUSD)/100)
		total := fmt.Sprintf("%.2f", float64(order.TotalUSD)/100)
		email := order.UserEmail
		product := order.FirstOrderItem.ProductName
		identifier := order.Identifier
		userName := order.UserName
		emailTemplate, err := os.ReadFile("emails/new-sale.html")

		if err != nil {
			return WriteJSON(w, http.StatusInternalServerError, ApiError{Message: "failed to read email template", Error: err.Error()})
		}

		emailBody := string(emailTemplate)

		emailBody = strings.Replace(emailBody, "{{.ProductName}}", product, 3)
		emailBody = strings.Replace(emailBody, "{{.UserName}}", userName, 1)
		emailBody = strings.Replace(emailBody, "{{.OrderNumber}}", orderNumber, 1)
		emailBody = strings.Replace(emailBody, "{{.CustomerEmail}}", email, 1)
		emailBody = strings.Replace(emailBody, "{{.Subtotal}}", subtotal, 1)
		emailBody = strings.Replace(emailBody, "{{.Total}}", total, 2)
		emailBody = strings.Replace(emailBody, "{{.Identifier}}", identifier, 1)

		err = util.SendEmail("cole@colecaccamise.com", fmt.Sprintf("New $%s sale of %s!", total, product), emailBody)

		if err != nil {
			return WriteJSON(w, http.StatusInternalServerError, ApiError{Message: "failed to send email", Error: err.Error()})
		}

		return WriteJSON(w, http.StatusOK, map[string]any{"message": "webhook received and handled", "order": order})
	default:
		fmt.Println("unsupported event detected:", event)
		return WriteJSON(w, http.StatusBadRequest, map[string]string{"message": "unsupported event"})
	}
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) error {
	signupReq := new(models.SignupRequest)
	if err := json.NewDecoder(r.Body).Decode(signupReq); err != nil {
		return WriteJSON(w, http.StatusBadRequest, ApiError{Message: "invalid request", Error: err.Error()})
	}

	if signupReq.Email == "" || signupReq.Password == "" {
		return WriteJSON(w, http.StatusBadRequest, ApiError{Message: "invalid request", Error: "email and password are required"})
	}

	eightOrMore, number, upper, special := util.ValidatePassword(signupReq.Password)

	var errorMessages []string
	if !eightOrMore {
		errorMessages = append(errorMessages, "be at least 8 characters long")
	}
	if !number {
		errorMessages = append(errorMessages, "contain at least one number")
	}
	if !upper {
		errorMessages = append(errorMessages, "contain at least one uppercase letter")
	}
	if !special {
		errorMessages = append(errorMessages, "contain at least one special character")
	}

	if len(errorMessages) > 0 {
		errorMessage := "Password must " + strings.Join(errorMessages, ", ")
		if len(errorMessages) > 1 {
			lastIndex := len(errorMessages) - 1
			errorMessage = strings.Join(errorMessages[:lastIndex], ", ") + ", and " + errorMessages[lastIndex]
			errorMessage = "Password must " + errorMessage
		}
		return WriteJSON(w, http.StatusBadRequest, ApiError{Message: "invalid request", Error: errorMessage})
	}

	hashedPassword, err := hashAndSaltPassword(signupReq.Password)
	if err != nil {
		return err
	}

	// store user in db
	user := models.NewUser(&models.CreateUserRequest{
		Email:          signupReq.Email,
		HashedPassword: hashedPassword,
	})

	if err := s.store.CreateUser(user); err != nil {
		return err
	}

	// generate auth confirmation token
	authToken, err := generateToken(user, "email_confirmation")
	if err != nil {
		return err
	}

	fmt.Println("auth token:", authToken)

	confirmationUrl := fmt.Sprintf("%s/auth/confirm?token=%s", os.Getenv("APP_URL"), authToken)

	fmt.Println("confirmation url:", confirmationUrl)
	// send confirmation email
	err = util.SendEmail(signupReq.Email, "Confirm your email", fmt.Sprintf("Click <a href=\"%s\">here</a> to confirm your email.", confirmationUrl))

	if err != nil {
		return err
	}

	// redirect to confirm-email page
	redirectUrl := fmt.Sprintf("%s/", os.Getenv("APP_URL"))

	return WriteJSON(w, http.StatusOK, map[string]string{"redirect_url": redirectUrl})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) error {
	loginReq := new(models.LoginRequest)
	if err := json.NewDecoder(r.Body).Decode(loginReq); err != nil {
		return err
	}

	user, err := s.store.GetUserByEmail(loginReq.Email)

	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, ApiError{Message: "invalid credentials", Error: "unauthorized"})
	}

	passwordMatches := comparePasswords(user.HashedPassword, loginReq.Password)
	if !passwordMatches {
		return WriteJSON(w, http.StatusUnauthorized, ApiError{Message: "invalid credentials", Error: "password does not match"})
	}

	return WriteJSON(w, http.StatusOK, map[string]any{"message": "login successful"})
}

func (s *Server) handleConfirmEmailToken(w http.ResponseWriter, r *http.Request) error {
	tokenReq := new(models.ConfirmEmailTokenRequest)
	if err := json.NewDecoder(r.Body).Decode(tokenReq); err != nil {
		return WriteJSON(w, http.StatusBadRequest, ApiError{Message: "invalid request", Error: err.Error()})
	}

	if tokenReq.Token == "" {
		return WriteJSON(w, http.StatusBadRequest, ApiError{Message: "invalid request", Error: "token is required"})
	}

	token, err := jwt.Parse(tokenReq.Token, func(token *jwt.Token) (any, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, ApiError{Message: "invalid token", Error: err.Error()})
	}

	userId, ok := token.Claims.(jwt.MapClaims)["user_id"]
	if !ok {
		return WriteJSON(w, http.StatusUnauthorized, ApiError{Message: "invalid token"})
	}

	uuid, err := uuid.Parse(userId.(string))
	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, ApiError{Message: "invalid token"})
	}

	user, err := s.store.GetUserByID(uuid)
	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, ApiError{Message: "invalid token"})
	}

	authToken, err := generateToken(user, "auth")
	if err != nil {
		return err
	}

	user.EmailConfirmedAt = time.Now()

	if err := s.store.UpdateUser(user); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name: "auth-token",
		Value: authToken,
		Path: "/",
		MaxAge: 60 * 15,
	})

	return WriteJSON(w, http.StatusOK, map[string]any{"message": "email confirmed"})
}

func hashAndSaltPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func comparePasswords(hashedPassword, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}

func generateToken(user *models.User, tokenType string) (string, error) {
	if tokenType != "auth" && tokenType != "refresh" && tokenType != "reset_password" && tokenType != "forgot_password" && tokenType != "email_confirmation" {
		return "", fmt.Errorf("invalid token type")
	}

	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp": func() int64 {
			if tokenType == "refresh" {
				return time.Now().Add(time.Hour * 24 * 90).Unix()
			}
			return time.Now().Add(time.Minute * 15).Unix()
		}(),
		"type": tokenType,
	}

	authToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedAuthToken, err := authToken.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", err
	}

	return signedAuthToken, nil
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) error {
	createUserReq := new(models.CreateUserRequest)
	if err := json.NewDecoder(r.Body).Decode(createUserReq); err != nil {
		return err
	}

	user := models.NewUser(createUserReq)

	if err := s.store.CreateUser(user); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, user)
}

func (s *Server) handleGetAllUsers(w http.ResponseWriter, r *http.Request) error {
	users, err := s.store.GetAllUsers()
	if err != nil {
		return err
	}
	return WriteJSON(w, http.StatusOK, users)
}

func (s *Server) handleGetUserByID(w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, ApiError{Message: "invalid id", Error: err.Error()})
	}

	user, err := s.store.GetUserByID(id)
	if err != nil {
		return WriteJSON(w, http.StatusNotFound, ApiError{Message: fmt.Sprintf("cannot %s %s", r.Method, r.URL.Path), Error: "user not found"})
	}

	return WriteJSON(w, http.StatusOK, user)
}

func (s *Server) handleDeleteUserByID(w http.ResponseWriter, r *http.Request) error {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, ApiError{Message: "invalid id", Error: err.Error()})
	}

	if err := s.store.DeleteUserByID(id); err != nil {
		return WriteJSON(w, http.StatusInternalServerError, ApiError{Message: "failed to delete user", Error: err.Error()})
	}

	return WriteJSON(w, http.StatusNoContent, nil)
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status) // this needs to be after setting content type
	return json.NewEncoder(w).Encode(v)
}

func makeHttpHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteJSON(w, http.StatusBadRequest, ApiError{Message: fmt.Sprintf("cannot %s %s", r.Method, r.URL.Path), Error: err.Error()})
		}
	}
}