package authorization_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"

	"trafficcontroller/authorization"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"trafficcontroller/uaa_client"
)

var _ = Describe("AdminAccessAuthorizer", func() {



})

type fakeUaaClient struct {
}

func (client *fakeUaaClient) GetAuthData(token string) (*uaa_client.AuthData, error) {

}
