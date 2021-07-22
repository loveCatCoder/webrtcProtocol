
#include "erizo/logger.h"
#include "WebrtcConn.h"

CWebrtcConn::CWebrtcConn(/* args */)
{

}

CWebrtcConn::~CWebrtcConn()
{

}

void CWebrtcConn::Init()
{
    
    InitSdp();

}

std::string CWebrtcConn::GetSdp() 
{
    std::string sdp = m_sdp->getSdp();
    return sdp;
}


void CWebrtcConn::InitSdp() 
{

    std::vector<RtpMap> rtp_mappings; //you may need to init the mappings
    RtpMap videoRtpmap;
    videoRtpmap.clock_rate = 90000;
    videoRtpmap.media_type = VIDEO_TYPE;
    videoRtpmap.payload_type = 96;
    videoRtpmap.encoding_name = "H264";
    videoRtpmap.channels = 1;
    rtp_mappings.push_back(videoRtpmap);

    RtpMap audioRtpmap;
    audioRtpmap.clock_rate = 8000;
    audioRtpmap.media_type = AUDIO_TYPE;
    audioRtpmap.payload_type = 8;
    audioRtpmap.encoding_name = "pcma";
    audioRtpmap.channels = 1;
    rtp_mappings.push_back(audioRtpmap);

    m_sdp = new SdpInfo(rtp_mappings);

    m_sdp->createOfferSdp(true,true,true);

    m_sdp->dtlsRole = ACTPASS;
    m_sdp->internal_dtls_role = PASSIVE;

    m_sdp->video_ssrc_map["video_label"] = {77777777};
    m_sdp->audio_ssrc_map["audio_label"] = 88888888;

    m_sdp->videoDirection = erizo::SENDONLY;
    m_sdp->audioDirection = erizo::SENDONLY;

    InitDtls();

    m_sdp->isFingerprint = true;
    m_sdp->fingerprint = m_dtlsTransport->GetLocalFingerprint();
    m_sdp->setCredentials(m_dtlsTransport->getLocalUsername(),m_dtlsTransport->getLocalPassword(),VIDEO_TYPE);
    m_sdp->setCredentials(m_dtlsTransport->getLocalUsername(),m_dtlsTransport->getLocalPassword(),AUDIO_TYPE);

    std::string sdp = m_sdp->getSdp();
    
}

void CWebrtcConn::InitDtls()
{
    m_dtlsTransport = std::make_shared<erizo::DtlsTransport>();
    m_dtlsTransport->SetTransportListener(shared_from_this());
    m_dtlsTransport->Init();
}

void CWebrtcConn::onCandidate(const CandidateInfo &candidate, IceConnection *conn) 
{
      std::string sdp = m_sdp->addCandidate(candidate);
}
