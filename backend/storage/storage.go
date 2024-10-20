package storage

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/colecaccamise/go-backend/models"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Storage interface {
	CreateUser(*models.User) error
	UpdateUser(*models.User) error
	GetAllUsers() ([]*models.User, error)
	GetUserByID(uuid.UUID) (*models.User, error)
	GetUserByEmail(string) (*models.User, error)
	DeleteUserByID(uuid.UUID) error
}

type PostgresStore struct {
	db *gorm.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	dsn := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s", os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_PORT"), os.Getenv("POSTGRES_DB"))

	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err == nil {
			fmt.Println("Connected to database!")
			return &PostgresStore{db: db}, nil
		}
		fmt.Printf("Waiting for database to be ready... (%d/%d)\n", i+1, maxRetries)
		time.Sleep(5 * time.Second)
	}

	return nil, fmt.Errorf("failed to connect to database after %d retries", maxRetries)
}

func (s *PostgresStore) Init() error {
	return s.CreateUsersTable()
}

func (s *PostgresStore) CreateUsersTable() error {
	return s.db.AutoMigrate(&models.User{})
}

func (s *PostgresStore) CreateUser(user *models.User) error {
	result := s.db.Create(user)
	return result.Error
}

func (s *PostgresStore) UpdateUser(user *models.User) error {
	result := s.db.Model(user).Updates(user)
	return result.Error
}

func (s *PostgresStore) GetUserByID(id uuid.UUID) (*models.User, error) {
	var user models.User
	result := s.db.First(&user, id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found with id %s", id)
		}
		return nil, result.Error
	}
	return &user, nil
}

func (s *PostgresStore) GetUserByEmail(email string) (*models.User, error) {
	var user models.User
	result := s.db.Where("email = ?", email).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found with email %s", email)
		}
		return nil, result.Error
	}
	return &user, nil
}

func (s *PostgresStore) GetAllUsers() ([]*models.User, error) {
	var users []*models.User
	result := s.db.Find(&users)
	if result.Error != nil {
		return nil, result.Error
	}
	return users, nil
}

func (s *PostgresStore) DeleteUserByID(id uuid.UUID) error {
	result := s.db.Delete(&models.User{}, id)
	return result.Error
}