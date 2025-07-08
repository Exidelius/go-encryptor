package sensitive

import (
	"log/slog"
	"reflect"

	"github.com/Exidelius/go-encryptor/internal/interfaces"
)

// FieldEncryptor реализует интерфейс interfaces.FieldEncryptor для шифрования полей в структурах
type FieldEncryptor struct {
	encryptor interfaces.Encryptor
}

// NewFieldEncryptor создает новый экземпляр FieldEncryptor
func NewFieldEncryptor(encryptor interfaces.Encryptor) *FieldEncryptor {
	return &FieldEncryptor{
		encryptor: encryptor,
	}
}

// HandleFields обрабатывает поля структуры, шифруя или расшифровывая их
func (h *FieldEncryptor) HandleFields(data interface{}, encrypt bool) (interface{}, error) {
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Struct {
		return nil, interfaces.ErrInvalidData
	}

	newVal := reflect.New(val.Elem().Type())
	newVal.Elem().Set(val.Elem())

	typ := val.Type()

	for i := 0; i < newVal.Elem().NumField(); i++ {
		field := newVal.Elem().Field(i)
		fieldType := typ.Field(i)

		slog.Info(fieldType.Tag.Get("encrypted"))
		// Проверяем тег encrypted
		if fieldType.Tag.Get("encrypted") != "true" {
			continue
		}
		if field.Kind() != reflect.String {
			continue
		}

		slog.Info("Мы тут бываем, да")
		value := field.String()
		var result string
		var err error

		if encrypt {
			result, err = h.encryptor.Encrypt(value)
		} else {
			result, err = h.encryptor.Decrypt(value)
		}

		if err != nil {
			return nil, err
		}

		slog.Info(result)
		field.SetString(result)
	}

	return newVal.Elem().Interface(), nil
}
