package channel_group_connector_test

import (
	"code.google.com/p/gogoprotobuf/proto"
	"errors"
	"github.com/cloudfoundry/dropsonde/events"
	"github.com/cloudfoundry/gosteno"
	"github.com/cloudfoundry/loggregatorlib/loggertesthelper"
	"sync/atomic"
	"time"
	"trafficcontroller/channel_group_connector"
	"trafficcontroller/listener"
	"trafficcontroller/serveraddressprovider"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"trafficcontroller/marshaller"
)

var _ = Describe("ChannelGroupConnector", func() {
	Describe("Connect", func() {
		var (
			logger              *gosteno.Logger
			provider            *serveraddressprovider.FakeServerAddressProvider
			fakeListeners       []*listener.FakeListener
			listenerConstructor func() listener.Listener
			messageChan1        chan []byte
			messageChan2        chan []byte
			expectedMessage1    = []byte{0}
			expectedMessage2    = []byte{1}
		)

		BeforeEach(func() {
			logger = loggertesthelper.Logger()
			provider = &serveraddressprovider.FakeServerAddressProvider{}

			messageChan1 = make(chan []byte, 1)
			messageChan2 = make(chan []byte, 1)
			fakeListeners = []*listener.FakeListener{
				listener.NewFakeListener(messageChan1, nil),
				listener.NewFakeListener(messageChan2, nil),
			}

			i := int32(-1)
			listenerConstructor = func() listener.Listener {
				atomic.AddInt32(&i, 1)
				return fakeListeners[i]
			}
		})

		Context("when reading 'recent' messages", func() {
			Context("from a single server", func() {
				BeforeEach(func() {
					messageChan1 <- expectedMessage1
					close(messageChan1)

					provider.SetServerAddresses([]string{"10.0.0.1:1234"})
				})

				AfterEach(func() {
					close(messageChan2)
				})

				It("opens a listener with the correct path", func() {
					channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)
					outputChan := make(chan []byte, 10)
					stopChan := make(chan struct{})
					defer close(stopChan)
					go channelConnector.Connect("/recentlogs", "abc123", outputChan, stopChan, true)

					Eventually(fakeListeners[0].ConnectedHost).Should(Equal("ws://10.0.0.1:1234/apps/abc123/recentlogs"))
				})

				It("opens a listener with the firehose path", func() {
					channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)
					outputChan := make(chan []byte, 10)
					stopChan := make(chan struct{})
					defer close(stopChan)
					go channelConnector.Connect("/firehose", "firehose", outputChan, stopChan, true)

					Eventually(fakeListeners[0].ConnectedHost).Should(Equal("ws://10.0.0.1:1234/firehose"))
				})

				It("puts messages on the channel received by the listener", func() {
					channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)
					outputChan := make(chan []byte)

					go func() {
						channelConnector.Connect("/recentlogs", "abc123", outputChan, make(chan struct{}), false)
					}()

					Eventually(outputChan).Should(Receive(Equal(expectedMessage1)))
				})
			})

			Context("from multiple servers", func() {
				BeforeEach(func() {
					messageChan1 <- expectedMessage1
					close(messageChan1)

					messageChan2 <- expectedMessage2
					close(messageChan2)

					provider.SetServerAddresses([]string{"10.0.0.1:1234", "10.0.0.2:1234"})

				})

				It("puts messages on the channel received by the listener", func(done Done) {
					channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)
					outputChan := make(chan []byte)

					go func() {
						channelConnector.Connect("/recentlogs", "abc123", outputChan, make(chan struct{}), false)
						close(done)
					}()

					receivedMessages := [][]byte{}

					for msg := range outputChan {
						receivedMessages = append(receivedMessages, msg)
					}

					Eventually(receivedMessages).Should(ConsistOf(expectedMessage1, expectedMessage2))
				})
			})
		})

		Context("when streaming messages", func() {
			AfterEach(func() {
				for _, l := range fakeListeners {
					l.Close()
				}
			})

			Context("from single server", func() {
				var (
					stopChan chan struct{}
				)

				BeforeEach(func() {
					stopChan = make(chan struct{})
					go sendMessages(messageChan1, expectedMessage1, stopChan)
					provider.SetServerAddresses([]string{"10.0.0.1:1234"})

				})

				AfterEach(func() {
					stopChan <- struct{}{}
					<-stopChan
				})

				It("receives multiple messages on the channel", func() {
					channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)
					outputChan := make(chan []byte, 10)

					stopChan := make(chan struct{})
					defer close(stopChan)
					go channelConnector.Connect("/stream", "abc123", outputChan, stopChan, true)

					Eventually(func() int { return len(outputChan) }).Should(BeNumerically(">", 1))
				})

				It("opens a listener with the correct path", func() {
					channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)
					outputChan := make(chan []byte, 10)
					stopChan := make(chan struct{})
					defer close(stopChan)
					go channelConnector.Connect("/stream", "abc123", outputChan, stopChan, true)

					Eventually(fakeListeners[0].ConnectedHost).Should(Equal("ws://10.0.0.1:1234/apps/abc123/stream"))
				})

				It("closes listeners and returns when stopChan is closed", func(done Done) {
					channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)

					outputChan := make(chan []byte, 10)
					stopChan := make(chan struct{})

					go func() {
						channelConnector.Connect("/stream", "abc123", outputChan, stopChan, true)
						close(done)
					}()

					close(stopChan)

					Eventually(fakeListeners[0].IsStopped).Should(BeTrue())
				})
			})

			Context("when streaming messages from multiple servers", func() {
				var (
					stopChan1 chan struct{}
					stopChan2 chan struct{}
				)

				BeforeEach(func() {
					stopChan1 = make(chan struct{})
					stopChan2 = make(chan struct{})

					go sendMessages(messageChan1, expectedMessage1, stopChan1)
					go sendMessages(messageChan2, expectedMessage2, stopChan2)

					provider.SetServerAddresses([]string{"10.0.0.1:1234", "10.0.0.2:1234"})
				})

				AfterEach(func() {
					stopChan1 <- struct{}{}
					stopChan2 <- struct{}{}
					<-stopChan1
					<-stopChan2
				})

				It("receives multiple messages from each sender", func() {
					channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)
					outputChan := make(chan []byte)

					stopChan := make(chan struct{})
					defer close(stopChan)

					go channelConnector.Connect("/stream", "abc123", outputChan, stopChan, false)

					counts := make([]int32, 2)

					go func() {
						for msg := range outputChan {
							atomic.AddInt32(&(counts[msg[0]]), 1)
						}
					}()

					Eventually(func() int32 { return counts[0] }).Should(BeNumerically(">", 1))
					Eventually(func() int32 { return counts[1] }).Should(BeNumerically(">", 1))
				})

				It("closes listeners and returns when stopChan is closed", func() {
					channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)

					outputChan := make(chan []byte, 10)
					stopChan := make(chan struct{})
					done := make(chan struct{})

					go func() {
						channelConnector.Connect("/stream", "abc123", outputChan, stopChan, true)
						close(done)
					}()

					close(stopChan)

					Eventually(done).Should(BeClosed())
					Eventually(fakeListeners[0].IsStopped).Should(BeTrue())
					Eventually(fakeListeners[1].IsStopped).Should(BeTrue())
				})
			})
		})

		Context("when an error is receieved from the listener", func() {
			BeforeEach(func() {
				messageChan := make(chan []byte, 10)
				fakeListeners[0] = listener.NewFakeListener(messageChan, errors.New("failure"))

				provider.SetServerAddresses([]string{"10.0.0.1:1234"})

			})

			AfterEach(func() {
				for _, l := range fakeListeners {
					l.Close()
				}
			})

			It("puts an error on the message channel when reading messages", func() {
				channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)

				stopChan := make(chan struct{})
				defer close(stopChan)
				go channelConnector.Connect("/stream", "abc123", messageChan1, stopChan, false)

				msg := &[]byte{}
				Eventually(messageChan1).Should(Receive(msg))
				envelope := &events.Envelope{}
				err := proto.Unmarshal(*msg, envelope)
				Expect(err).NotTo(HaveOccurred())

				Expect(envelope.GetAppId()).To(Equal("abc123"))
				Expect(envelope.GetLogMessage().GetMessage()).To(BeEquivalentTo("proxy: error connecting to 10.0.0.1:1234: failure"))
			})
		})

		Context("when streaming messages from a single server and a listener error occurrs", func() {
			BeforeEach(func() {
				messageChan1 <- expectedMessage1

				fakeListeners[0].SetReadError(errors.New("boom"))

				provider.SetServerAddresses([]string{"10.0.0.1:1234"})

			})

			AfterEach(func() {
				for _, l := range fakeListeners {
					l.Close()
				}
			})

			It("puts a message about the error on the channel ", func() {
				channelConnector := channel_group_connector.NewChannelGroupConnector(provider, listenerConstructor, marshaller.DropsondeLogMessage, logger)
				outputChan := make(chan []byte)

				stopChan := make(chan struct{})
				defer close(stopChan)
				go channelConnector.Connect("/stream", "abc123", outputChan, stopChan, true)

				msg := <-outputChan
				receivedEnvelope := &events.Envelope{}
				err := proto.Unmarshal(msg, receivedEnvelope)
				Expect(err).NotTo(HaveOccurred())

				Expect(receivedEnvelope.GetAppId()).To(Equal("abc123"))
				Expect(receivedEnvelope.GetLogMessage().GetMessage()).To(ContainSubstring("boom"))
			})
		})

	})
})

func sendMessages(messageChan chan<- []byte, envBytes []byte, stopChan chan struct{}) {
	ticker := time.NewTicker(150 * time.Millisecond)

	for {
		select {
		case <-ticker.C:
			messageChan <- envBytes
		case <-stopChan:
			close(stopChan)
			ticker.Stop()
			return
		}
	}
}
