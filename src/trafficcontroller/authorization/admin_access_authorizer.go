package authorization

import (
	"fmt"
	"github.com/cloudfoundry/gosteno"
	"trafficcontroller/uaa_client"
)

type AdminAccessAuthorizer func(authToken string, logger *gosteno.Logger) bool

func NewAdminAccessAuthorizer(client *uaa_client.UaaClient, skipCertVerify bool) AdminAccessAuthorizer {

	isAccessAllowed := func(authToken string, logger *gosteno.Logger) bool {
		//		auth = Uaa.validateToken(authToken)
		//		if auth.hasPermission("uaa.admin") || auth.hasPermission("loggregator.admin") {
		//			return true
		//		}

		fmt.Println("AdminAccesAuthorizer : %s", authToken)
		//		if authToken == "validToken" {
		return true
		//		}
		//
		//		return false
	}

	return AdminAccessAuthorizer(isAccessAllowed)
}
