package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/colecaccamise/go-backend/middleware"
	"github.com/colecaccamise/go-backend/models"
	"github.com/colecaccamise/go-backend/storage"
	"github.com/colecaccamise/go-backend/util"
	"github.com/go-chi/chi"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/h2non/filetype"
	"github.com/rs/cors"
	"github.com/stripe/stripe-go/v80"
	"golang.org/x/crypto/bcrypt"
)

type Error struct {
	Message string `json:"message"`
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
}

type Response struct {
	Message string `json:"message"`
	Data    string `json:"data"`
	Code    string `json:"code,omitempty"`
}

type apiFunc func(http.ResponseWriter, *http.Request) error

type Server struct {
	listenAddr string
	store      storage.Storage
}

func NewServer(listenAddr string, store storage.Storage) *Server {
	return &Server{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (s *Server) Start() error {
	r := chi.NewRouter()
	stripe.Key = os.Getenv("STRIPE_KEY")

	r.NotFound(makeHttpHandleFunc(handleNotFound))
	r.MethodNotAllowed(makeHttpHandleFunc(handleMethodNotAllowed))

	r.Get("/uuid", makeHttpHandleFunc(func(w http.ResponseWriter, r *http.Request) error {
		return WriteJSON(w, http.StatusOK, map[string]string{"uuid": uuid.New().String()})
	}))

	r.Route("/auth", func(r chi.Router) {
		r.Get("/identity", makeHttpHandleFunc(s.handleIdentity))
		r.Post("/refresh", makeHttpHandleFunc(s.handleRefreshToken))
		r.Post("/signup", makeHttpHandleFunc(s.handleSignup))
		r.Post("/resend-email", makeHttpHandleFunc(s.handleResendEmail))
		r.Post("/login", makeHttpHandleFunc(s.handleLogin))
		r.Post("/logout", makeHttpHandleFunc(s.handleLogout))
		r.Post("/confirm", makeHttpHandleFunc(s.handleConfirmEmailToken))
	})

	r.Route("/tokens", func(r chi.Router) {
		r.Get("/", makeHttpHandleFunc(s.handleGetAllTokens))
		// r.Post("/", makeHttpHandleFunc(s.handleCreateToken))
		// r.Delete("/{id}", makeHttpHandleFunc(s.handleDeleteToken))
	})

	r.Group(func(r chi.Router) {
		r.Use(middleware.VerifyAuth)
		r.Post("/auth/verify-password", makeHttpHandleFunc(s.handleVerifyPassword))
	})

	// TODO: secure these routes to admins only
	//r.Group(func(r chi.Router) {
	//	r.Use(middleware.VerifyAuth)
	//	r.Route("/users", func(r chi.Router) {
	//		r.Post("/", makeHttpHandleFunc(s.handleCreateUser))
	//		r.Get("/", makeHttpHandleFunc(s.handleGetAllUsers))
	//		r.Get("/{id}", makeHttpHandleFunc(s.handleGetUserByID))
	//		r.Patch("/{id}", makeHttpHandleFunc(s.handleUpdateUserByID))
	//		r.Patch("/{id}/email", makeHttpHandleFunc(s.handleUpdateUserEmailByID))
	//		r.Post("/{id}/resend-email", makeHttpHandleFunc(s.handleResendUpdateEmailByID))
	//		r.Delete("/{id}", makeHttpHandleFunc(s.handleDeleteUserByID))
	//		r.Patch("/{id}/avatar", makeHttpHandleFunc(s.handleUploadAvatarByID))
	//	})
	//})

	// user taking actions on their own account they're logged in to
	r.Group(func(r chi.Router) {
		r.Use(middleware.VerifyAuth)
		r.Route("/users", func(r chi.Router) {
			r.Patch("/", makeHttpHandleFunc(s.handleUpdateUser))
			r.Patch("/email", makeHttpHandleFunc(s.handleUpdateUserEmail))
			r.Post("/resend-email", makeHttpHandleFunc(s.handleResendUpdateEmail))
			r.Delete("/", makeHttpHandleFunc(s.handleDeleteUser))
			r.Patch("/avatar", makeHttpHandleFunc(s.handleUploadAvatar))
		})
	})

	stack := middleware.CreateStack(
		middleware.Logging,
		middleware.Nosniff,
	)

	fmt.Println("Server is running on port", s.listenAddr)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:8000", "https://colecaccamise.com"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Content-Type", "Location"},
		AllowOriginFunc: func(origin string) bool {
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
	return WriteJSON(w, http.StatusNotFound, Error{Message: fmt.Sprintf("cannot %s %s", req.Method, req.URL.Path), Error: "route not found"})
}

func handleMethodNotAllowed(w http.ResponseWriter, req *http.Request) error {
	return WriteJSON(w, http.StatusMethodNotAllowed, Error{Message: fmt.Sprintf("cannot %s %s", req.Method, req.URL.Path), Error: "method not allowed"})
}

func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) error {
	// Read in auth token
	authToken, err := r.Cookie("auth-token")

	if err != nil {
		// If no auth token, check for refresh token
		refreshToken, err := r.Cookie("refresh-token")
		if err != nil {
			return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user is not authenticated", Error: "no tokens found"})
		}

		// Parse and check if refresh token is valid
		userId, tokenType, err := util.ParseJWT(refreshToken.Value)
		if err != nil || tokenType != "refresh" {
			return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user is not authenticated", Error: "invalid refresh token"})
		}

		// If valid, generate auth token and set cookie, then return user
		user, err := s.store.GetUserByID(uuid.MustParse(userId))
		if err != nil {
			http.SetCookie(w, &http.Cookie{
				Name:    "auth-token",
				Value:   "",
				Path:    "/",
				Expires: time.Unix(0, 0),
			})
			http.SetCookie(w, &http.Cookie{
				Name:    "refresh-token",
				Value:   "",
				Path:    "/",
				Expires: time.Unix(0, 0),
			})
			return WriteJSON(w, http.StatusBadRequest, Error{Message: "user not found", Error: err.Error()})
		}

		userData := models.NewUserIdentityResponse(user)

		authToken, err := generateToken(user, "auth")
		if err != nil {
			return err
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "auth-token",
			Value:    authToken,
			Path:     "/",
			MaxAge:   60 * 15,
			HttpOnly: true,
		})

		return WriteJSON(w, http.StatusOK, userData)
	}

	// Parse auth token
	userId, tokenType, err := util.ParseJWT(authToken.Value)
	if err != nil || tokenType != "auth" || userId == "" {
		// If invalid, check for refresh token
		refreshToken, err := r.Cookie("refresh-token")
		if err != nil {
			return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user is not authenticated", Error: "invalid token"})
		}

		// Parse and check if refresh token is valid
		userId, tokenType, err = util.ParseJWT(refreshToken.Value)
		if err != nil || tokenType != "refresh" {
			return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user is not authenticated", Error: "invalid token"})
		}
	}

	// If valid, return user
	userData, err := s.store.GetUserByID(uuid.MustParse(userId))
	if err != nil {
		http.SetCookie(w, &http.Cookie{
			Name:    "auth-token",
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),
		})
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user not found", Error: err.Error()})
	}

	token, err := generateToken(userData, "auth")
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth-token",
		Value:    token,
		Path:     "/",
		MaxAge:   60 * 15,
		HttpOnly: true,
	})

	user := models.NewUserIdentityResponse(userData)

	return WriteJSON(w, http.StatusOK, user)
}

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) error {
	refreshToken, err := r.Cookie("refresh-token")
	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user is not authenticated", Error: err.Error()})
	}

	userId, authTokenType, err := util.ParseJWT(refreshToken.Value)
	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user is not authenticated", Error: err.Error()})
	}

	if authTokenType != "refresh" {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user is not authenticated", Error: "unauthorized"})
	}

	user, err := s.store.GetUserByID(uuid.MustParse(userId))
	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user is not authenticated", Error: err.Error()})
	}

	authToken, err := generateToken(user, "auth")
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth-token",
		Value:    authToken,
		Path:     "/",
		MaxAge:   60 * 15,
		HttpOnly: true,
	})

	return WriteJSON(w, http.StatusOK, nil)
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) error {
	signupReq := new(models.SignupRequest)

	if err := json.NewDecoder(r.Body).Decode(signupReq); err != nil {
		errorMsg := "invalid request"
		if err == io.EOF {
			errorMsg = "request body is empty"
		}
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid request", Error: errorMsg})
	}

	if signupReq.Email == "" || signupReq.Password == "" {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid request", Error: "email and password are required"})
	}

	existingUser, _ := s.store.GetUserByEmail(signupReq.Email)
	if existingUser != nil {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "cannot signup", Error: "an account with this email already exists"})
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
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid request", Error: errorMessage})
	}

	hashedPassword, err := hashAndSaltPassword(signupReq.Password)
	if err != nil {
		return err
	}

	// create user object
	user := models.NewUser(&models.CreateUserRequest{
		Email:          signupReq.Email,
		HashedPassword: hashedPassword,
	})

	// store user object in db
	if err := s.store.CreateUser(user); err != nil {
		return err
	}

	// generate auth confirmation token
	confirmationToken, err := generateToken(user, "email_confirmation")
	if err != nil {
		return err
	}

	// generate email resend token
	emailResendToken, err := generateToken(user, "email_resend")
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "email-resend-token",
		Value:    emailResendToken,
		Path:     "/",
		MaxAge:   60 * 60 * 24,
		HttpOnly: true,
	})

	confirmationUrl := fmt.Sprintf("%s/auth/confirm?token=%s", os.Getenv("APP_URL"), confirmationToken)

	// send confirmation email
	err = util.SendEmail(signupReq.Email, "Confirm your email", fmt.Sprintf("Click here to confirm your email: %s", confirmationUrl))

	if err != nil {
		return err
	}

	// generate auth tokens
	authToken, err := generateToken(user, "auth")
	if err != nil {
		return err
	}

	refreshToken, err := generateToken(user, "refresh")
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth-token",
		Value:    authToken,
		Path:     "/",
		MaxAge:   60 * 15,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh-token",
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   60 * 60 * 24 * 90,
		HttpOnly: true,
	})

	// redirect to confirm-email page
	redirectUrl := fmt.Sprintf("%s/auth/confirm-email?email=%s", os.Getenv("APP_URL"), signupReq.Email)

	return WriteJSON(w, http.StatusOK, map[string]string{"redirect_url": redirectUrl})
}

func (s *Server) handleResendEmail(w http.ResponseWriter, r *http.Request) error {
	authToken, err := r.Cookie("auth-token")

	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user is not authenticated", Error: err.Error()})
	}

	userId, authTokenType, err := util.ParseJWT(authToken.Value)
	if err != nil || authTokenType != "auth" {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "user is not authenticated", Error: err.Error()})
	}

	user, err := s.store.GetUserByID(uuid.MustParse(userId))
	if err != nil {
		fmt.Printf("Error getting user: %v\n", err)
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "invalid token", Error: err.Error()})
	}

	// verify users email isn't already confirmed
	if user.EmailConfirmedAt != nil {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "email already confirmed", Error: "email already confirmed"})
	}

	emailConfirmationToken, err := generateToken(user, "email_confirmation")
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return err
	}

	confirmationUrl := fmt.Sprintf("%s/auth/confirm?token=%s", os.Getenv("APP_URL"), emailConfirmationToken)

	err = util.SendEmail(user.Email, "Confirm your email", fmt.Sprintf("Click here to confirm your email: %s", confirmationUrl))

	if err != nil {
		fmt.Printf("Error sending email: %v\n", err)
		return err
	}

	return WriteJSON(w, http.StatusOK, nil)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) error {
	// TODO: check that user isnt already logged in
	loginReq := new(models.LoginRequest)
	if err := json.NewDecoder(r.Body).Decode(loginReq); err != nil {
		return err
	}

	user, err := s.store.GetUserByEmail(loginReq.Email)

	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "invalid credentials", Error: "unauthorized"})
	}

	passwordMatches := comparePasswords(user.HashedPassword, loginReq.Password)
	if !passwordMatches {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "invalid credentials", Error: "invalid email or password"})
	}

	authToken, err := generateToken(user, "auth")
	if err != nil {
		return err
	}

	refreshToken, err := generateToken(user, "refresh")
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth-token",
		Value:    authToken,
		Path:     "/",
		MaxAge:   60 * 15,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh-token",
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   60 * 60 * 24 * 90,
		HttpOnly: true,
	})

	return WriteJSON(w, http.StatusOK, nil)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) error {
	http.SetCookie(w, &http.Cookie{
		Name:    "auth-token",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	})

	http.SetCookie(w, &http.Cookie{
		Name:    "refresh-token",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	})

	http.SetCookie(w, &http.Cookie{
		Name:    "email-resend-token",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	})

	return WriteJSON(w, http.StatusOK, nil)
}

func (s *Server) handleConfirmEmailToken(w http.ResponseWriter, r *http.Request) error {
	tokenReq := new(models.ConfirmEmailTokenRequest)
	if err := json.NewDecoder(r.Body).Decode(tokenReq); err != nil {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid request", Error: err.Error()})
	}

	if tokenReq.Token == "" {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid request", Error: "token is required"})
	}

	token, err := jwt.Parse(tokenReq.Token, func(token *jwt.Token) (any, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "invalid token", Error: err.Error()})
	}

	userId, ok := token.Claims.(jwt.MapClaims)["user_id"]
	if !ok {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "invalid token"})
	}

	uuid, err := uuid.Parse(userId.(string))
	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "invalid token"})
	}

	user, err := s.store.GetUserByID(uuid)
	if err != nil {
		return WriteJSON(w, http.StatusUnauthorized, Error{Message: "invalid token"})
	}

	authToken, err := generateToken(user, "auth")
	if err != nil {
		return err
	}

	refreshToken, err := generateToken(user, "refresh")
	if err != nil {
		return err
	}

	now := time.Now()

	if user.UpdatedEmail != "" {
		user.Email = user.UpdatedEmail
		user.UpdatedEmail = ""
		user.UpdatedEmailConfirmedAt = &now
	} else {
		user.EmailConfirmedAt = &now
	}

	if err := s.store.UpdateUser(user); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth-token",
		Value:    authToken,
		Path:     "/",
		MaxAge:   60 * 15,
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh-token",
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   60 * 60 * 24 * 90,
		HttpOnly: true,
	})

	cookies := w.Header()["Set-Cookie"]
	if len(cookies) == 0 {
		fmt.Println("Warning: No cookies were set in the response headers")
	} else {
		fmt.Println("Cookies set in response headers:", cookies)
	}

	return WriteJSON(w, http.StatusOK, map[string]any{"message": "email confirmed"})
}

func (s *Server) handleVerifyPassword(w http.ResponseWriter, r *http.Request) error {
	return nil
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
	if tokenType != "auth" && tokenType != "refresh" && tokenType != "reset_password" && tokenType != "forgot_password" && tokenType != "email_confirmation" && tokenType != "email_resend" && tokenType != "password_verification" {
		return "", fmt.Errorf("invalid token type")
	}

	claims := jwt.MapClaims{
		"user_id": user.ID,
		"exp": func() int64 {
			if tokenType == "refresh" {
				return time.Now().Add(time.Hour * 24 * 90).Unix()
			}
			if tokenType == "email_resend" {
				return time.Now().Add(time.Hour * 24).Unix()
			}
			if tokenType == "password_verification" {
				return time.Now().Add(time.Minute * 10).Unix()
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

func getUserIdentity(s *Server, r *http.Request) (user models.User, authType string, err error) {
	if s == nil || r == nil {
		return models.User{}, "", fmt.Errorf("both server and request not provided")
	}

	// check for auth token
	authToken, e := r.Cookie("auth-token")
	apiKey := r.Header.Get("X-API-KEY")

	// no auth token or api key
	if apiKey == "" && e != nil {
		return models.User{}, "", e
	}

	// verify auth token
	if authToken != nil {
		userId, authTokenType, e := util.ParseJWT(authToken.Value)

		// bad auth token, no api key
		if e != nil && apiKey == "" {
			return models.User{}, "", e
		}

		if userId != "" && authTokenType == "auth" {
			user, err := s.store.GetUserByID(uuid.MustParse(userId))

			// user doesn't exist, no api key
			if err != nil && apiKey == "" {
				return models.User{}, "", err
			}

			if user == nil && apiKey == "" {
				return models.User{}, "", fmt.Errorf("invalid user")
			}

			// return user object
			if user != nil {
				return *user, "authToken", nil
			}
		}

		// TODO: implement identity for api key
		if apiKey != "" {
			return models.User{}, "", fmt.Errorf("identity not implemented for api keys")
		}
	}

	return models.User{}, "", nil
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
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid id", Error: err.Error()})
	}

	user, err := s.store.GetUserByID(id)
	if err != nil {
		return WriteJSON(w, http.StatusNotFound, Error{Message: fmt.Sprintf("cannot %s %s", r.Method, r.URL.Path), Error: "user not found"})
	}

	return WriteJSON(w, http.StatusOK, user)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) error {
	user, _, err := getUserIdentity(s, r)
	if err != nil {
		return err
	}

	updateUserReq := new(models.UpdateUserRequest)
	if err := json.NewDecoder(r.Body).Decode(updateUserReq); err != nil {
		return err
	}

	user.FirstName = updateUserReq.FirstName
	user.LastName = updateUserReq.LastName

	if err := s.store.UpdateUser(&user); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, user)
}

func (s *Server) handleUpdateUserEmail(w http.ResponseWriter, r *http.Request) error {
	user, _, err := getUserIdentity(s, r)
	if err != nil {
		return err
	}

	updateUserEmailReq := new(models.UpdateUserEmailRequest)
	if err := json.NewDecoder(r.Body).Decode(updateUserEmailReq); err != nil {
		return err
	}

	if updateUserEmailReq.Email == user.Email {
		fmt.Println("email is the same")
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "email is the same", Error: "email is the same", Code: "email_update_unchanged"})
	}

	// validate user with requested email doesn't exist
	existingUser, _ := s.store.GetUserByEmail(updateUserEmailReq.Email)

	if existingUser != nil {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "email taken", Error: "a user with this email already exists", Code: "email_taken"})
	}

	user.UpdatedEmail = updateUserEmailReq.Email
	now := time.Now()
	user.UpdatedEmailAt = &now

	if err := s.store.UpdateUser(&user); err != nil {
		return err
	}

	// send email confirmation
	emailConfirmationToken, err := generateToken(&user, "email_confirmation")
	if err != nil {
		return err
	}

	confirmationUrl := fmt.Sprintf("%s/auth/confirm?token=%s", os.Getenv("APP_URL"), emailConfirmationToken)

	err = util.SendEmail(user.UpdatedEmail, "Confirm your email", fmt.Sprintf("Please confirm your email by clicking <a href=\"%s\">here</a>", confirmationUrl))
	if err != nil {
		fmt.Printf("Error sending email: %v\n", err)
		return err
	}

	fmt.Println("email confirmation url:", confirmationUrl)

	return WriteJSON(w, http.StatusOK, map[string]any{"message": "email updated", "updated_email": user.UpdatedEmail, "email": user.Email})
}

func (s *Server) handleResendUpdateEmail(w http.ResponseWriter, r *http.Request) error {
	// check that user has outstanding email update request

	// get updated email

	// send email

	return WriteJSON(w, http.StatusOK, map[string]any{"message": "email sent"})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) error {
	user, _, err := getUserIdentity(s, r)
	if err != nil {
		return err
	}

	if err := s.store.DeleteUserByID(user.ID); err != nil {
		return WriteJSON(w, http.StatusInternalServerError, Error{Message: "failed to delete user", Error: err.Error()})
	}

	return WriteJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleUploadAvatar(w http.ResponseWriter, r *http.Request) error {
	file, fileHeader, err := r.FormFile("avatar")

	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid request", Error: err.Error()})
	}

	if file == nil {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid request", Error: "file is required"})
	}

	buf, err := io.ReadAll(file)
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid request", Error: err.Error()})
	}

	fileType, err := filetype.MatchReader(bytes.NewReader(buf))
	if err != nil {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid request", Error: err.Error()})
	}

	if fileType.MIME.Value != "image/jpeg" && fileType.MIME.Value != "image/png" {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "invalid request", Error: "file must be a jpeg or png"})
	}

	fmt.Println("file type:", fileType.MIME.Value)

	if fileHeader.Size > 2000000 {
		return WriteJSON(w, http.StatusBadRequest, Error{Message: "file too large", Error: "file too large"})
	}

	// filename, _, err := util.UploadFileToS3(buf)
	// if err != nil {
	// 	return err
	// }

	// cloudfrontUrl := fmt.Sprintf("%s/%s", os.Getenv("CLOUDFRONT_URL"), filename)

	// user, err := s.store.GetUserByID(uuid.MustParse(chi.URLParam(r, "id")))
	// if err != nil {
	// 	return WriteJSON(w, http.StatusNotFound, ApiError{Message: "user not found", Error: err.Error()})
	// }

	// user.AvatarUrl = cloudfrontUrl

	// if err := s.store.UpdateUser(user); err != nil {
	// 	return err
	// }

	// return WriteJSON(w, http.StatusOK, map[string]any{"location": cloudfrontUrl, "file_type": fileType})

	return WriteJSON(w, http.StatusOK, map[string]any{"location": "", "file_type": fileType})
}

func (s *Server) handleGetAllTokens(w http.ResponseWriter, r *http.Request) error {
	// get current user from auth token
	//authToken, err := r.Cookie("auth-token")
	//
	//if err != nil {
	//	return WriteJSON(w, http.StatusUnauthorized, ApiError{Message: "user is not authenticated", Error: err.Error()})
	//}
	//
	//userId, authTokenType, err := util.ParseJWT(authToken.Value)
	//if err != nil || authTokenType != "auth" {
	//	return WriteJSON(w, http.StatusUnauthorized, ApiError{Message: "user is not authenticated", Error: err.Error()})
	//}

	//user, err := s.store.GetUserByID(uuid.MustParse(userId))
	//if err != nil {
	//	return WriteJSON(w, http.StatusUnauthorized, ApiError{Message: "user is not authenticated", Error: err.Error()})
	//}

	// get all of their api tokens from db
	//tokens, err := s.store.GetAPITokensByUserID(user.ID)
	//if err != nil {
	//	return WriteJSON(w, http.StatusInternalServerError, ApiError{Message: "error getting tokens", Error: err.Error()})
	//}

	return WriteJSON(w, http.StatusOK, nil)
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status) // this needs to be after setting content type
	return json.NewEncoder(w).Encode(v)
}

func makeHttpHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteJSON(w, http.StatusBadRequest, Error{Message: fmt.Sprintf("cannot %s %s", r.Method, r.URL.Path), Error: err.Error()})
		}
	}
}
