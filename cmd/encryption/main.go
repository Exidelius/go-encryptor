package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Exidelius/go-encryptor/pkg/config"
	"github.com/Exidelius/go-encryptor/pkg/encryption"

	"github.com/Exidelius/go-encryptor/internal/configfile"
)

var (
	// Ключ шифрования в формате base64 или как есть
	key = flag.String("key", "", "32-byte encryption key")
	// Путь к конфигурационному файлу
	configPath = flag.String("config", "configs/config.default.yml", "path to YAML config file")
	// Пароли для шифрования (через запятую)
	passwords = flag.String("passwords", "", "comma-separated list of passwords to encrypt")
	// Поля в конфигурации (через запятую)
	fields = flag.String("fields", "", "comma-separated list of fields to update (e.g. redis.password,database.password)")
	// Флаг для вывода справки
	helpFlag = flag.Bool("help", false, "show help message")
	hFlag    = flag.Bool("h", false, "show help message (shorthand)")
	// Флаг для дебага
	debugFlag = flag.Bool("debug", false, "enable debug output")
)

// UserConfig пример структуры с чувствительными данными
type UserConfig struct {
	Username string `encrypted:"false"`
	Password string `encrypted:"true"`
	APIKey   string `encrypted:"true"`
	Email    string `encrypted:"true"`
}

func printUsage() {
	fmt.Println("Usage examples:")
	fmt.Println("1. Encrypt multiple passwords:")
	fmt.Println("   ./encrypt -key=\"your-32-byte-key\" -passwords=\"secret123,password456,key789\"")
	fmt.Println("2. Update multiple config fields:")
	fmt.Println("   ./encrypt -key=\"your-32-byte-key\" -config=\"config.yml\" -fields=\"database.password,redis.password\" -passwords=\"secret123,password456\"")
	fmt.Println()
	fmt.Println("How to generate a 32-byte key (base64) with openssl:")
	fmt.Println("   openssl rand -base64 32")
	fmt.Println("Use the result as the -key argument.")
	os.Exit(0)
}

func main() {
	flag.Parse()

	configfile.SetDebug(*debugFlag)

	if *helpFlag || *hFlag {
		printUsage()
	}

	// Проверяем обязательные параметры
	if *key == "" {
		log.Fatal("encryption key is required")
	}

	// Создаем конфигурацию с ключом шифрования
	cfg, err := config.NewConfig(*key)
	if err != nil {
		log.Fatalf("Failed to create config: %v", err)
	}

	// Создаем шифратор
	encryptor, err := encryption.NewEncryptor(cfg)
	if err != nil {
		log.Fatalf("Failed to create encryptor: %v", err)
	}

	// Сначала проверяем: если переданы все параметры для обновления конфига — только обновляем файл
	if *configPath != "" && *fields != "" && *passwords != "" {
		fieldList := strings.Split(*fields, ",")
		for i := range fieldList {
			fieldList[i] = strings.TrimSpace(fieldList[i])
		}
		passwordList := strings.Split(*passwords, ",")
		for i := range passwordList {
			passwordList[i] = strings.TrimSpace(passwordList[i])
		}
		if len(fieldList) != len(passwordList) {
			log.Fatalf("number of fields and passwords must match")
		}
		// Шифруем пароли
		encrypted := make([]string, len(passwordList))
		for i, pwd := range passwordList {
			enc, err := encryptor.EncryptString(pwd)
			if err != nil {
				log.Fatalf("Failed to encrypt password '%s': %v", pwd, err)
			}
			encrypted[i] = enc
		}
		if err := configfile.UpdateConfigFile(*configPath, fieldList, encrypted); err != nil {
			log.Fatalf("Failed to update config: %v", err)
		}
		fmt.Println("Config updated successfully!")
		os.Exit(0)
	}

	// Если только -passwords (без -config и -fields) — просто выводим зашифрованные пароли
	if *passwords != "" {
		passwordList := strings.Split(*passwords, ",")
		for _, pwd := range passwordList {
			pwd = strings.TrimSpace(pwd)
			if pwd == "" {
				continue
			}
			encrypted, err := encryptor.EncryptString(pwd)
			if err != nil {
				log.Printf("Failed to encrypt password '%s': %v", pwd, err)
				continue
			}
			fmt.Printf("Password: %s\nEncrypted: %s\n\n", pwd, encrypted)
		}
		os.Exit(0)
	}

	// Если не указаны параметры, показываем примеры использования
	printUsage()
}
