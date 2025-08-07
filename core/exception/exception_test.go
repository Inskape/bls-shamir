package exception_test

import (
	"Inskape/bls-shamir/core/exception"
	"errors"
	"testing"
)

func TestNewException(t *testing.T) {
	testErr := errors.New("test error")
	e := exception.ErrPublicKeyGeneration(testErr)
	if !errors.Is(e, exception.ErrPublicKeyGeneration()) {
		t.Errorf("[%v] is not wrapped by [%v]", e, exception.ErrPublicKeyGeneration())
	}
}
