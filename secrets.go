package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

var (
	ErrNotFound      = errors.New("secret not found")
	ErrFailedRequest = errors.New("request failed")
	ErrUnAuthorized  = errors.New("request not authorized")
)

// ThirdSecretAPI implements a http request handler for the imaginary ThirdSecret.
type ThirdSecretAPI struct {
	Client *http.Client

	Addr   string
	APIKey string
}

// Get returns giving secret for provided key from third party.
func (th *ThirdSecretAPI) Get(key string) (string, error) {
	var req, err = http.NewRequest("GET", th.prepareURL(key), nil)
	if err != nil {
		return "", err
	}

	var res *http.Response
	res, err = th.Client.Do(req)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	if res.StatusCode == http.StatusUnauthorized {
		return "", ErrUnAuthorized
	}

	if res.StatusCode >= 200 && res.StatusCode <= 299 {
		var bu bytes.Buffer
		if _, err := io.Copy(&bu, res.Body); err != nil {
			return "", err
		}

		return bu.String(), nil
	}

	if res.StatusCode == http.StatusNotFound {
		return "", ErrNotFound
	}

	return "", ErrFailedRequest
}

func (th *ThirdSecretAPI) prepareURL(val string) string {
	var m = url.Values{}
	m.Add("key", val)
	m.Add("api_key", th.APIKey)
	return fmt.Sprintf("%s?%s", th.Addr, m.Encode())
}
