# Openstack Plugin Grpc Service

## grpc 代码生成

```
python3 -m grpc_tools.protoc --python_out=internal/lcmservice --grpc_python_out=internal/lcmservice -I internal/lcmservice lcmservice.proto
```

## 依赖

```
pip install -r requirements.txt
```

## 启动环境变量
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
|BASE_DIR|path|基础路径|/app|
|LOG_DIR|path|日志路径|/app/log|
|IMAGE_CHUNK_SIZE|byte|镜像分片大小(单位: 字节)|1 * 1024 * 1024|
|SERVER_CA_VERIFY_DIR|path/false|openstack ssl配置(信任证书路径或false不校验证书)|false|