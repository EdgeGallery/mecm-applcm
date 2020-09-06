package pluginAdapter

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"lcmcontroller/pkg/plugin"
	"lcmcontroller/util"
)

const (
	chunkSize = 1024
)

// Get client based on client protocol type
func GetClient(pluginInfo string) (client ClientIntf, err error) {
	clientProtocol := util.GetAppConfig("clientProtocol")
	switch clientProtocol {
	case "grpc":
		clientConfig := plugin.ClientGRPCConfig{Address: pluginInfo, ChunkSize: chunkSize,
			RootCertificate: "HTTPSClientCA"}
		var client, err = plugin.NewClientGRPC(clientConfig)
		if err != nil {
			log.Errorf(util.FailedToCreateClient, err)
			return nil, err
		}
		return client, nil
	default:
		return nil, errors.New("no client is found")
	}
}
