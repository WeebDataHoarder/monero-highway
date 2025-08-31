package utils

import (
	"strings"
)

type MultiStringFlag []string

func (f *MultiStringFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *MultiStringFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}
