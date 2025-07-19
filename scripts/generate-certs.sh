#!/bin/bash
set -e

# 证书目录
CERT_DIR="certs"
mkdir -p $CERT_DIR

# 证书参数
DAYS=3650
COUNTRY="CN"
STATE="Beijing"
CITY="Beijing"
ORGANIZATION="OpenEDR Dev"
ORGANIZATIONAL_UNIT="Development"

echo "Generating development certificates..."

# 生成CA私钥
openssl genrsa -out $CERT_DIR/ca.key 4096

# 生成CA证书
openssl req -new -x509 -days $DAYS -key $CERT_DIR/ca.key -out $CERT_DIR/ca.crt \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=OpenEDR CA"

# 生成服务器私钥
openssl genrsa -out $CERT_DIR/server.key 4096

# 生成服务器证书请求
openssl req -new -key $CERT_DIR/server.key -out $CERT_DIR/server.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=localhost"

# 创建扩展配置文件
cat > $CERT_DIR/server.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = openedr-server
DNS.4 = *.openedr.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# 签发服务器证书
openssl x509 -req -in $CERT_DIR/server.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key \
    -CAcreateserial -out $CERT_DIR/server.crt -days $DAYS -sha256 -extfile $CERT_DIR/server.ext

# 生成Agent客户端私钥
openssl genrsa -out $CERT_DIR/agent.key 4096

# 生成Agent客户端证书请求
openssl req -new -key $CERT_DIR/agent.key -out $CERT_DIR/agent.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=openedr-agent"

# 创建Agent扩展配置文件
cat > $CERT_DIR/agent.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF

# 签发Agent证书
openssl x509 -req -in $CERT_DIR/agent.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key \
    -CAcreateserial -out $CERT_DIR/agent.crt -days $DAYS -sha256 -extfile $CERT_DIR/agent.ext

# 生成测试用的客户端私钥
openssl genrsa -out $CERT_DIR/client.key 4096

# 生成测试客户端证书请求
openssl req -new -key $CERT_DIR/client.key -out $CERT_DIR/client.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=test-client"

# 签发测试客户端证书
openssl x509 -req -in $CERT_DIR/client.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key \
    -CAcreateserial -out $CERT_DIR/client.crt -days $DAYS -sha256 -extfile $CERT_DIR/agent.ext

# 清理临时文件
rm -f $CERT_DIR/*.csr $CERT_DIR/*.ext $CERT_DIR/ca.srl

# 设置权限
chmod 600 $CERT_DIR/*.key
chmod 644 $CERT_DIR/*.crt

echo "Certificates generated successfully!"
echo ""
echo "Certificate files:"
echo "  CA Certificate: $CERT_DIR/ca.crt"
echo "  CA Private Key: $CERT_DIR/ca.key"
echo "  Server Certificate: $CERT_DIR/server.crt"
echo "  Server Private Key: $CERT_DIR/server.key"
echo "  Agent Certificate: $CERT_DIR/agent.crt"
echo "  Agent Private Key: $CERT_DIR/agent.key"
echo "  Test Client Certificate: $CERT_DIR/client.crt"
echo "  Test Client Private Key: $CERT_DIR/client.key"
echo ""
echo "To verify certificates:"
echo "  openssl verify -CAfile $CERT_DIR/ca.crt $CERT_DIR/server.crt"
echo "  openssl verify -CAfile $CERT_DIR/ca.crt $CERT_DIR/agent.crt" 