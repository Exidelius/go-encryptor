package sensitive

import (
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

	newVal := reflect.New(val.Type())
	newVal.Set(val.Elem())

	typ := newVal.Type()

	for i := 0; i < newVal.NumField(); i++ {
		field := newVal.Field(i)
		fieldType := typ.Field(i)

		// Проверяем тег encrypted
		if fieldType.Tag.Get("encrypted") != "true" {
			continue
		}
		if field.Kind() != reflect.String {
			continue
		}

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

		field.SetString(result)
	}

	return newVal.Interface(), nil
}
