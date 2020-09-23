# mecm-applcm

#### Description
Application life cycle manager is part of MEP manager whose responsibility is to handle the host level life cycle management including  Instantiation, Termination etc. it provides a pluggable architecture to support multiple infrastructure. Currently Kubernetes based plugin is available for usage.

#### Compile and build
The AppLcm project is containerized based on docker, and it is divided into two steps during compilation and construction.

#### Compile
AppLcm is a GOLANG program written based on GOLANG 1.14.

#### Build image
The AppLcm project provides a dockerfile file for mirroring. You can use the following commands when making a mirror

docker build -t edgegallery/mecm-lcmcontroller:latest -f docker/Dockerfile .
docker build -t edgegallery/mecm-k8splugin:latest -f docker/Dockerfile .