package secrets_test

import (
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/influx6/secrets"
	"github.com/stretchr/testify/require"
)

var secretStore = map[string]string{
	"tricka": randomString(300),
	"bear":   randomString(300),
	"racket": randomString(300),
}

func TestThirdSecretAPI(t *testing.T) {
	var key = "wee-1232323-22354765565-3446576"
	var server = createMapSecrets(key, secretStore)
	require.NotNil(t, server)

	defer server.Close()

	var client = &secrets.ThirdSecretAPI{
		APIKey: key,
		Addr:   server.URL,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	require.NotNil(t, client)

	// create series of possible table tests to verify
	// behaviour of third party API.
	var testCases = []struct {
		Key      string
		Expected string
		NotFound bool
		Failed   bool
	}{
		{
			Key:      "bear",
			Expected: secretStore["bear"],
		},
		{
			Key:      "racket",
			Expected: secretStore["racket"],
		},
		{
			Key:      "drimdall",
			NotFound: true,
		},
		{
			Key:      "reckingball",
			NotFound: true,
		},
		{
			Key:      "13434",
			NotFound: true,
		},
		{
			Key:    "",
			Failed: true,
		},
	}

	for _, testCase := range testCases {
		secretValue, err := client.Get(testCase.Key)

		// if test case is verifying failure path, then check
		// that returned error matches failed request.
		if testCase.Failed {
			require.Error(t, err)
			require.Equal(t, secrets.ErrFailedRequest, err)
			continue
		}

		// if test case is verifying existing then check
		// expected error.
		if testCase.NotFound {
			require.Error(t, err)
			require.Equal(t, secrets.ErrNotFound, err)
			continue
		}

		// verify no error occurred and we have expected value.
		// should fail otherwise
		require.NoError(t, err)
		require.Equal(t, testCase.Expected, secretValue)
	}
}

func TestInvalidAuthKeyThirdSecretAPI(t *testing.T) {
	var server = createMapSecrets("dont_know", secretStore)
	require.NotNil(t, server)

	defer server.Close()

	var client = &secrets.ThirdSecretAPI{
		APIKey: "wrecker-balls",
		Addr:   server.URL,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	require.NotNil(t, client)

	_, err := client.Get("racket")
	require.Error(t, err)
	require.Equal(t, secrets.ErrUnAuthorized, err)
}

func createMapSecrets(key string, secrets map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.FormValue("key") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("api_key") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.FormValue("api_key") != key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if secret, ok := secrets[r.FormValue("key")]; ok {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(secret)); err != nil {
				log.Printf("Failed to write body of response: %s", err.Error())
			}
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

func createFailingServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
}

func randomString(len int) string {
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		bytes[i] = byte(65 + rand.Intn(25)) //A=65 and Z = 65+25
	}
	return string(bytes)
}
