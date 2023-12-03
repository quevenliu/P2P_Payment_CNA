if [ ! -d "$1" ]; then
    mkdir -p "$1"
fi
if [ ! -d "$2" ]; then
    mkdir -p "$2"
fi
openssl genrsa -out "${1}/server.key" 4096
openssl req -x509 -new -nodes -key "${1}/server.key" -subj "/C=TW/ST=Taiwan/L=Taipei/O=NTU/OU=IM/CN=ntu.edu.tw" -sha256 -days 2048 -out "${1}/server.crt"
openssl x509 -pubkey -noout -in "${1}/server.crt" > "${1}/server.pem"
openssl genrsa -out "${2}/client.key" 4096
openssl req -x509 -new -nodes -key "${2}/client.key" -subj "/C=TW/ST=Taiwan/L=Taipei/O=NTU/OU=IM/CN=ntu.edu.tw" -sha256 -days 2048 -out "${2}/client.crt"
openssl x509 -pubkey -noout -in "${2}/client.crt" > "${2}/client.pem"
