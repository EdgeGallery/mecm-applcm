# Openstack Plugin Grpc Service

## grpc 代码生成

```
python3 -m grpc_tools.protoc --python_out=internal/lcmservice --grpc_python_out=internal/lcmservice -I internal/lcmservice lcmservice.proto
```
