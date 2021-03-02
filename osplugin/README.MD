# Openstack Plugin Grpc Service

## grpc 代码生成
python3 -m grpc_tools.protoc -I . --python_out=. --grpc_python_out=. ./internal/lcmservice/lcmservice.proto