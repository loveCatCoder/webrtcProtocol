# webrtcProtocol
test webrtc transport protocol

##生成私钥 
openssl genrsa -out rsa_private.key 1024
openssl req -new -x509 -days 36500 -key rsa_private.key -out cert.crt


IceConnection -> DtlsTransport

browser           ------------------------------------------            server

                                getsdp
                  ------------------->>>>>>>>>>>>>>>>>>>>>>>>>


                                server-sdp
                  <<<<<<<<<<<<<<<<<<<<-----------------------


                                client-sdp
                  ---------------------->>>>>>>>>>>>>>>>>>>>   

                                client-candidate
                  ---------------------->>>>>>>>>>>>>>>>>>>>   


本地服务器需要生成rsa私钥和证书，Fingerprint是对本地证书的sha256位摘要，dtls交换证书后验证指纹，不正确会导致dtls握手失败

MyIceConnection创建一个socket,获取到绑定的ip，端口，然后写到服务器的sdp信息里

MyIceConnection使用随机字符串生成账号，密码并初始化到服务器的sdp信息里


如何生成sdp

使用rtpMap 作为构造函数的参数构造SdpInfo
SdpInfo.CreateOfferSdp
设置SdpInfo.dtlsRole


当前任务
使用sdpinfo生成sdp,获取到dtls握手交换到的密钥


正确的使用到的webrtcconn接口流程

createOffer

init()
addMediaStream


setRemoteSdp
addRemoteCandidate
m_webrtcConn->getLocalSdpInfo();
m_webrtcConn->getLocalSdp();
构造函数

m_webrtcConn->setRemoteSdp(sdp);
