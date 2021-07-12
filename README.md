# webrtcProtocol
test webrtc transport protocol

##生成私钥 
openssl genrsa -out rsa_private.key 1024
openssl req -new -x509 -days 36500 -key rsa_private.key -out cert.crt
