package interfaces

import (
	"github.com/Exidelius/go-encryptor/pkg/config"
)

// Encryptor определяет интерфейс для шифрования данных
type Encryptor interface {
	Encrypt(text string) (string, error)
	Decrypt(encrypted string) (string, error)
}

// EncryptorProvider определяет интерфейс для предоставления шифровальщиков
type EncryptorProvider interface {
	ProvideEncryptor(cfg *config.Config) (Encryptor, error)
}

// FieldEncryptor определяет интерфейс для шифрования полей в структурах
type FieldEncryptor interface {
	HandleFields(data interface{}, encrypt bool) (interface{}, error)
}
