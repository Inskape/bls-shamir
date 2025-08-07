package encode

import "encoding/base64"

const (
	// custom base64 encoding
	// names of serf nodes only allow alpha-numerics, dashes, and '.'
	encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-."
)

var Base64 = base64.NewEncoding(encoding).WithPadding(base64.NoPadding)
