package errors

import (
	"errors"
	"fmt"
)

func Wrap(msg string, err error) error {
	return errors.New(fmt.Sprintf("%s: %s", msg, err.Error()))
}
