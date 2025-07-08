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

	// Создаём копию структуры
	newVal := reflect.New(val.Elem().Type())
	newVal.Elem().Set(val.Elem())

	// Обрабатываем поля
	if err := h.processStruct(newVal.Elem(), encrypt); err != nil {
		return nil, err
	}

	return newVal.Elem().Interface(), nil
}

// Рекурсивная функция обработки структуры
func (h *FieldEncryptor) processStruct(v reflect.Value, encrypt bool) error {
	typ := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := typ.Field(i)

		// Обработка вложенных структур
		if field.Kind() == reflect.Struct {
			if err := h.processStruct(field, encrypt); err != nil {
				return err
			}
			continue
		}

		// Обработка указателей на структуры
		if field.Kind() == reflect.Ptr && field.Type().Elem().Kind() == reflect.Struct {
			if field.IsNil() {
				continue // Пропускаем nil-указатели
			}
			if err := h.processStruct(field.Elem(), encrypt); err != nil {
				return err
			}
			continue
		}

		// Пропускаем поля без тега или не-строки
		if fieldType.Tag.Get("encrypted") != "true" || field.Kind() != reflect.String {
			continue
		}

		// Шифрование/дешифрование
		value := field.String()
		var result string
		var err error

		if encrypt {
			result, err = h.encryptor.Encrypt(value)
		} else {
			result, err = h.encryptor.Decrypt(value)
		}

		if err != nil {
			return err
		}

		field.SetString(result)
	}
	return nil
}
