package uaa_client_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"trafficcontroller/uaa_client"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("UaaClient", func() {
	handler := new(fakeUaaHandler)
	fakeUaaServer := httptest.NewServer(handler)

	Context("when the user is an admin", func() {
		It("Determines permissions from correct credentials", func() {
			uaaClient := uaa_client.NewUaaClient(fakeUaaServer.URL, "bob", "yourUncle")

			authData, err := uaaClient.GetAuthData("iAmAnAdmin")
			Expect(err).ToNot(HaveOccurred())

			Expect(authData.HasPermission("uaa.admin")).To(Equal(true))
			Expect(authData.HasPermission("uaa.not-admin")).To(Equal(false))

		})
	})

	Context("when the user is not an admin", func() {
		It("Determines permissions from correct credentials", func() {
			uaaClient := uaa_client.NewUaaClient(fakeUaaServer.URL, "bob", "yourUncle")

			authData, err := uaaClient.GetAuthData("iAmNotAnAdmin")
			Expect(err).ToNot(HaveOccurred())

			Expect(authData.HasPermission("uaa.admin")).To(Equal(false))
			Expect(authData.HasPermission("uaa.not-admin")).To(Equal(true))
		})
	})

	Context("the token is expired", func() {
		It("returns the proper error", func() {
			uaaClient := uaa_client.NewUaaClient(fakeUaaServer.URL, "bob", "yourUncle")

			_, err := uaaClient.GetAuthData("expiredToken")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Token has expired"))
		})
	})

	Context("the token is invalid", func() {
		It("returns the proper error", func() {
			uaaClient := uaa_client.NewUaaClient(fakeUaaServer.URL, "bob", "yourUncle")

			_, err := uaaClient.GetAuthData("invalidToken")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Invalid token (could not decode): invalidToken"))
		})
	})

	Context("the server returns a 500 ", func() {
		It("returns the proper error", func() {
			uaaClient := uaa_client.NewUaaClient(fakeUaaServer.URL, "bob", "yourUncle")

			_, err := uaaClient.GetAuthData("500Please")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Unknown error occurred"))
		})
	})

	Context("the un/pwd is invalid", func() {
		It("returns the proper error", func() {
			uaaClient := uaa_client.NewUaaClient(fakeUaaServer.URL, "wrongUser", "yourUncle")

			_, err := uaaClient.GetAuthData("iAmAnAdmin")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("Invalid username/password"))
		})
	})
})

type fakeUaaHandler struct {
}

func (h *fakeUaaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/check_token" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if r.Header.Get("Authorization") != "Basic Ym9iOnlvdXJVbmNsZQ==" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("{\"error\":\"unauthorized\",\"error_description\":\"No client with requested id: wrongUser\"}"))
		return
	}

	token := r.FormValue("token")

	if token == "iAmAnAdmin" {
		authData := map[string]interface{}{
			"scope": []string{
				"uaa.admin",
			},
		}

		marshaled, _ := json.Marshal(authData)
		w.Write(marshaled)
	} else if token == "iAmNotAnAdmin" {
		authData := map[string]interface{}{
			"scope": []string{
				"uaa.not-admin",
			},
		}

		marshaled, _ := json.Marshal(authData)
		w.Write(marshaled)
	} else if token == "expiredToken" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("{\"error\":\"invalid_token\",\"error_description\":\"Token has expired\"}"))
	} else if token == "invalidToken" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("{\"invalidToken\":\"invalid_token\",\"error_description\":\"Invalid token (could not decode): invalidToken\"}"))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}

}
