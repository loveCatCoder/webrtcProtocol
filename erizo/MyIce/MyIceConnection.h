//
// Created by xueyuegui on 19-12-6.
//

#ifndef MYWEBRTC_MYICECONNECTION_H
#define MYWEBRTC_MYICECONNECTION_H


#include <openssl/e_os2.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>


#include "IceConnection.h"
#include <vector>
#include <queue>
#include <map>
#include <mutex>  // NOLINT
#include <future>
#include <memory>
#include <string>

#include "MediaDefinitions.h"
#include "SdpInfo.h"
#include "logger.h"
#include "IceConnection.h"

#include "UdpSocket.h"
#include "Utils.hpp"
#include "IceServer.h"
#include "net/EventLoop.h"


namespace erizo {
    class MyIceConnection : public IceConnection {
    public:
        MyIceConnection(xop::EventLoop *loop,IceConfig& ice_config);

        ~MyIceConnection();

        void start() override;

        bool setRemoteCandidates(const std::vector<CandidateInfo> &candidates, bool is_bundle) override;

        void setRemoteCredentials(const std::string &username, const std::string &password) override;

        int sendData(unsigned int component_id, const void *buf, int len) override;

        void onData(unsigned int component_id, char *buf, int len) override;

        CandidatePair getSelectedPair() override;

        void setReceivedLastCandidate(bool hasReceived) override;

        void close() override;

        void OnPacketReceived(char* buf, int len, struct sockaddr_in* remoteAddr);
        void OnIceServerCompleted();
        int SendPacket(char * buf, int len, struct sockaddr_in* remoteAddr);
        int GetPort();

        void computeFingerprint(X509 *cert, char *fingerprint);

    private:
        std::shared_ptr<IceServer> m_ice_server;
        std::shared_ptr<UdpSocket> m_udp_socket;
        xop::EventLoop *m_loop;
        std::string m_strIp;
        uint16_t  m_nPort;
        struct sockaddr_in m_remoteAddr;
    };

}
#endif //MYWEBRTC_MYICECONNECTION_H
