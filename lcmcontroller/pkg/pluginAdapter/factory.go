package pluginAdapter

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"lcmcontroller/util"
)

const (
	chunkSize = 1024
	clientProtocol = "grpc"
)

// Get client based on client protocol type
func GetClient(pluginInfo string) (client ClientIntf, err error) {
	// To support testability requirement client protocol is not taken from config currently.
	switch clientProtocol {
	case "grpc":
		clientConfig := ClientGRPCConfig{Address: pluginInfo, ChunkSize: chunkSize,
			RootCertificate: "HTTPSClientCA"}
		var client, err = NewClientGRPC(clientConfig)
		if err != nil {
			log.Errorf(util.FailedToCreateClient, err)
			return nil, err
		}
		return client, nil
	default:
		return nil, errors.New("no client is found")
	}
}
