package doppler_endpoint_test

import (
	"trafficcontroller/doppler_endpoint"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("GetPath", func() {
	It("returns correct path for firehose", func() {
		dopplerEndpoint := doppler_endpoint.NewDopplerEndpoint("firehose", "firehose", true, doppler_endpoint.WebsocketHandlerProvider)
		Expect(dopplerEndpoint.GetPath()).To(Equal("/firehose"))
	})

	It("returns correct path for recentlogs", func() {
		dopplerEndpoint := doppler_endpoint.NewDopplerEndpoint("recentlogs", "abc123", true, doppler_endpoint.WebsocketHandlerProvider)
		Expect(dopplerEndpoint.GetPath()).To(Equal("/apps/abc123/recentlogs"))
	})
})
