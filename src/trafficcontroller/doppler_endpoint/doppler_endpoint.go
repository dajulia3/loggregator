package doppler_endpoint

import (
	"net/http"
	"github.com/cloudfoundry/gosteno"
	"github.com/cloudfoundry/loggregatorlib/server/handlers"
	"time"
)

var WebsocketKeepAliveDuration = 30 * time.Second


type DopplerConnector struct{
	Endpoint string
	StreamId string
	Reconnect bool
	HProvider HandlerProvider
}

func NewDopplerConnector(
  endpoint string,
  streamId string,
  reconnect bool,
	hProvider HandlerProvider,
) *DopplerConnector {

  return &DopplerConnector{
		Endpoint: endpoint,
		StreamId: streamId,
		Reconnect: reconnect,
		HProvider: hProvider,
	}
}

type HandlerProvider func(<-chan []byte, *gosteno.Logger) http.Handler

func HttpHandlerProvider(messages <-chan []byte, logger *gosteno.Logger) http.Handler {
	return handlers.NewHttpHandler(messages, logger)
}

func WebsocketHandlerProvider(messages <-chan []byte, logger *gosteno.Logger) http.Handler {
	return handlers.NewWebsocketHandler(messages, WebsocketKeepAliveDuration, logger)
}
