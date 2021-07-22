


#ifndef _WEBRTC_CONN_H_
#define _WEBRTC_CONN_H_


#include "erizo/SdpInfo.h"
#include "dtls/DtlsTransport.h"

using namespace erizo;

class CWebrtcConn: public  TransportListener,
                   public std::enable_shared_from_this<CWebrtcConn>
{
private:
    /* data */
public:
    CWebrtcConn(/* args */);
    ~CWebrtcConn();
    void Init();
    std::string GetSdp();

    virtual void onCandidate(const CandidateInfo &candidate, IceConnection *conn) override;
private:
    void InitDtls() ;
    void InitSdp() ;
private:
    SdpInfo *m_sdp;
    std::shared_ptr<erizo::DtlsTransport> m_dtlsTransport;
};


#endif
