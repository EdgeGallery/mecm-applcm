# Openstack Plugin Grpc Service

## 依赖

```
pip install -r requirements.txt
```

## 本地启动

+ 修改环境变量配置BASE_DIR

+ 拷贝 ./config-pro.ini 到 $BASE_DIR/config.ini

+ 修改config.ini的配置为本地配置

+ python3 main.py


## 个性化项目配置

### 启动环境变量
|变量名|类型|说明|默认值|
|---|---|----|----|
|ENABLE_SSL|true/false|启用ssl|false|
|LISTEN_IP|ip|监听ip|0.0.0.0|
|JWT_PUBLIC_KEY|pem|jwt验证公钥|-|
|DB_USER|string|数据库用户|osplugin|
|DB_PASSWORD|string|数据库密码|-|
|DB_HOST|ip|数据库host|127.0.0.1|
|DB_PORT|number|数据库端口|5432|
|DB_NAME|string|数据库名称|osplugindb|
|BASE_DIR|path|基础路径|.|
|LOG_DIR|path|日志路径|$BASE_DIR/log|
|SERVER_CA_VERIFY_DIR|path/false|openstack ssl配置(信任证书路径或false不校验证书)|false|

### 重新生成 grpc 代码

```shell
python3 -m grpc_tools.protoc --python_out=internal/lcmservice --grpc_python_out=internal/lcmservice -I internal/lcmservice lcmservice.proto
python3 -m grpc_tools.protoc --python_out=internal/resourcemanager --grpc_python_out=internal/resourcemanager -I internal/resourcemanager resourcemanager.proto

sed -i 's/import lcmservice_pb2 as lcmservice__pb2/import internal.lcmservice.lcmservice_pb2 as lcmservice__pb2/g' internal/lcmservice/lcmservice_pb2_grpc.py
sed -i 's/import resourcemanager_pb2 as resourcemanager__pb2/import internal.resourcemanager.resourcemanager as resourcemanager__pb2/g' internal/resourcemanager/resourcemanager_pb2_grpc.py
```