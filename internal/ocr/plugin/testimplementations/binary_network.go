package testimplementations

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/smartcontractkit/libocr/commontypes"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

type Network struct {
	mutex                          sync.Mutex
	chs                            map[types.ConfigDigest][]chan types.InboundBinaryMessageWithSender
	n                              int
	maxBufferedInboundMsgPerOracle int
}

// Initializes a new in-memory binary network for n oracles, each with a buffer size of maxBufferedInboundMsgPerOracle.
// When the buffer is full, new inbound messages are dropped.
func NewNetwork(n int, maxBufferedInboundMsgPerOracle int) *Network {
	return &Network{
		sync.Mutex{},
		map[types.ConfigDigest][]chan types.InboundBinaryMessageWithSender{},
		n,
		maxBufferedInboundMsgPerOracle,
	}
}

func (n *Network) EndpointFactory(
	id commontypes.OracleID,
	peerID string,
) types.BinaryNetworkEndpoint2Factory {
	return &EndpointFactory{n, id, peerID, n.maxBufferedInboundMsgPerOracle}
}

type EndpointFactory struct {
	Net                            *Network
	ID                             commontypes.OracleID
	PeerID_                        string
	maxBufferedInboundMsgPerOracle int
}

var _ types.BinaryNetworkEndpoint2Factory = (*EndpointFactory)(nil)

func clearChannel(ch chan types.InboundBinaryMessageWithSender) {
	for {
		select {
		case <-ch:
			// drain the channel
		default:
			// channel is empty
			return
		}
	}
}

func (epf *EndpointFactory) NewEndpoint(
	configDigest types.ConfigDigest,
	_ []string,
	_ []commontypes.BootstrapperLocator,
	_ types.BinaryNetworkEndpoint2Config,
	_ types.BinaryNetworkEndpoint2Config,

) (
	types.BinaryNetworkEndpoint2, error,
) {
	epf.Net.mutex.Lock()
	defer epf.Net.mutex.Unlock()

	chs, ok := epf.Net.chs[configDigest]
	if !ok {
		chs = make([]chan types.InboundBinaryMessageWithSender, epf.Net.n)
		for i := 0; i < epf.Net.n; i++ {
			chs[i] = make(chan types.InboundBinaryMessageWithSender, epf.maxBufferedInboundMsgPerOracle)
		}
		epf.Net.chs[configDigest] = chs
	} else {
		clearChannel(chs[epf.ID])
	}

	return &EndPoint{
		epf.Net,
		configDigest,
		epf.ID,
		chs,
	}, nil
}

func (epf *EndpointFactory) PeerID() string {
	return epf.PeerID_
}

type EndPoint struct {
	Net          *Network
	ConfigDigest types.ConfigDigest
	ID           commontypes.OracleID
	Chs          []chan types.InboundBinaryMessageWithSender
}

var _ types.BinaryNetworkEndpoint2 = (*EndPoint)(nil)

func (ep *EndPoint) toInboundMsgWithSender(outMsg types.OutboundBinaryMessage) (types.InboundBinaryMessageWithSender, error) {
	var inMsg types.InboundBinaryMessage

	switch msg := outMsg.(type) {
	case types.OutboundBinaryMessagePlain:
		inMsg = types.InboundBinaryMessagePlain(msg)

	case types.OutboundBinaryMessageRequest:
		policy := msg.ResponsePolicy.(types.SingleUseSizedLimitedResponsePolicy)
		inMsg = types.InboundBinaryMessageRequest{
			&requestHandle{policy.MaxSize, policy.ExpiryTimestamp, msg.Priority},
			msg.Payload,
			msg.Priority,
		}

	case types.OutboundBinaryMessageResponse:
		handle := types.MustGetOutboundBinaryMessageResponseRequestHandle(msg).(*requestHandle)

		// Check the response is well-formed
		if len(msg.Payload) > handle.maxSize {
			return types.InboundBinaryMessageWithSender{}, fmt.Errorf("response too large: %d > %d", len(msg.Payload), handle.maxSize)
		}

		// Check the response is not expired
		if !time.Now().Before(handle.expiryTimestamp) {
			return types.InboundBinaryMessageWithSender{}, fmt.Errorf("response expired at %v", handle.expiryTimestamp)
		}

		inMsg = types.InboundBinaryMessageResponse{msg.Payload, msg.Priority}

	default:
		panic("unknown type of types.OutboundBinaryMessage")
	}

	res := types.InboundBinaryMessageWithSender{inMsg, ep.ID}
	return res, nil
}

func (ep *EndPoint) SendTo(
	msg types.OutboundBinaryMessage, to commontypes.OracleID,
) {
	inMsg, err := ep.toInboundMsgWithSender(msg)
	if err == nil {
		select {
		case ep.Chs[to] <- inMsg:
			// Sent
		case <-time.After(100 * time.Millisecond):
			// drop the message if the buffer is full
			log.Println("send timed out")
		}
	}
}

func (ep *EndPoint) Broadcast(msg types.OutboundBinaryMessage) {
	for i := 0; i < len(ep.Chs); i++ {
		ep.SendTo(msg, commontypes.OracleID(i))
	}
}

func (ep *EndPoint) Receive() <-chan types.InboundBinaryMessageWithSender {
	return ep.Chs[ep.ID]
}

func (ep *EndPoint) Close() error { return nil }

var _ types.RequestHandle = (*requestHandle)(nil)

type requestHandle struct {
	maxSize         int
	expiryTimestamp time.Time
	priority        types.BinaryMessageOutboundPriority
}

func (rh *requestHandle) MakeResponse(payload []byte) types.OutboundBinaryMessageResponse {
	return types.MustMakeOutboundBinaryMessageResponse(
		rh,
		payload,
		rh.priority,
	)
}
