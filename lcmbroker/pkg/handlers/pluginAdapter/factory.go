package pluginAdapter

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"lcmbroker/pkg/plugin"
	"lcmbroker/util"
)

const (
	chunkSize       = 1024
	rootCertificate = ""
)

// Get client based on client protocol type
func GetClient(pluginInfo string) (client ClientIntf, err error) {
	clientProtocol := util.GetAppConfig("clientProtocol")
	switch clientProtocol {
	case "grpc":
		clientConfig := plugin.ClientGRPCConfig{Address: pluginInfo, ChunkSize: chunkSize,
			RootCertificate: rootCertificate}
		var client, err = plugin.NewClientGRPC(clientConfig)
		if err != nil {
			log.Errorf(util.FailedToCreateClient, err)
			return &client, err
		}

		return &client, nil
	default:
		return client, errors.New("no client is found")
	}
}
