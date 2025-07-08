package encryption

import (
	"github.com/Exidelius/go-encryptor/internal/interfaces"
	"github.com/Exidelius/go-encryptor/pkg/config"
)

// EncryptorProvider реализует интерфейс interfaces.EncryptorProvider
// для предоставления экземпляров шифровальщиков

type EncryptorProvider struct{}

// NewEncryptorProvider создает новый провайдер шифровальщиков
func NewEncryptorProvider() *EncryptorProvider {
	return &EncryptorProvider{}
}

// ProvideEncryptor предоставляет новый экземпляр шифровальщика
func (p *EncryptorProvider) ProvideEncryptor(cfg *config.Config) (interfaces.Encryptor, error) {
	return NewEncryptor(cfg.Key)
}
