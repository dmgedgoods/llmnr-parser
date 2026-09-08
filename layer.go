package llmnr

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LayerTypeLLMNR uses an application-defined ID, outside gopacket's built-ins.
var LayerTypeLLMNR = gopacket.RegisterLayerType(2001, gopacket.LayerTypeMetadata{
	Name: "LLMNR", Decoder: gopacket.DecodeFunc(decodeLLMNR),
})

var registerUDP sync.Once

// RegisterUDP enables automatic LLMNR decoding for UDP port 5355 globally.
// Call before starting packet decoding goroutines. This replaces any existing
// mapping for that port. gopacket checks destination then source port.
func RegisterUDP() {
	registerUDP.Do(func() { layers.RegisterUDPPortLayerType(5355, LayerTypeLLMNR) })
}

// Layer is the gopacket application layer for a decoded LLMNR message.
// BaseLayer.Contents references the supplied packet bytes, as in gopacket layers.
type Layer struct {
	layers.BaseLayer
	Message
}

func (*Layer) LayerType() gopacket.LayerType     { return LayerTypeLLMNR }
func (*Layer) CanDecode() gopacket.LayerClass    { return LayerTypeLLMNR }
func (*Layer) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// Payload returns the application message bytes, including the LLMNR header.
func (l *Layer) Payload() []byte { return l.Contents }

func (l *Layer) DecodeFromBytes(data []byte, feedback gopacket.DecodeFeedback) error {
	*l = Layer{}
	if len(data) < HeaderSize {
		feedback.SetTruncated()
	}
	message, err := DecodeMessage(data)
	if err != nil {
		return err
	}
	l.BaseLayer = layers.BaseLayer{Contents: data}
	l.Message = *message
	return nil
}

func decodeLLMNR(data []byte, p gopacket.PacketBuilder) error {
	layer := &Layer{}
	if err := layer.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(layer)
	p.SetApplicationLayer(layer)
	return nil
}
