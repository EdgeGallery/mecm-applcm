# mecm-applcm

#### 描述
mecm-applcm是负责边缘节点上的应用生命周期管理的模块，通常部署在边缘上负责本地应用生命周期管理。它实现了一种插件机制，以支持边缘上不同类型的基础设施。目前K8S 和OpenStack是已经支持的基础设施。

#### 编译和构建
APPLCM是基于docker容器化的项目，包含编译和构建两个步骤。

#### 编译
APPLCM是基于GOLANG 1.14的go语言的项目，开发人员可以使用go编译applcm项目。

#### 编译镜像
APPLCM目前包含三个容器，分别是lcmcontroller和k8splugin以及osplugin，开发人员可以使用如下命令进行镜像构建：
docker build -t edgegallery/mecm-lcmcontroller:latest -f docker/Dockerfile .
docker build -t edgegallery/mecm-k8splugin:latest -f docker/Dockerfile .
docker build -t edgegallery/mecm-osplugin:latest -f docker/Dockerfile .