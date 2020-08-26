package pluginAdapter

import (
	log "github.com/sirupsen/logrus"
	"lcmbroker/pkg/plugin"
	"lcmbroker/util"
)

// Get client based on client protocol type
func GetClient(pluginInfo string) (client plugin.ClientGRPC, err error) {
	clientProtocol := util.GetAppConfig("clientProtocol")
	switch clientProtocol {
	case "grpc":
		clientConfig := plugin.ClientGRPCConfig{Address: pluginInfo, ChunkSize: chunkSize,
			RootCertificate: rootCertificate}
		var client, err = plugin.NewClientGRPC(clientConfig)
		if err != nil {
			log.Errorf(util.FailedToCreateClient, err)
			return client, err
		}
		return client, nil
	default:
		return
	}
}
