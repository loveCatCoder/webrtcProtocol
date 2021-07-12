#ifndef _DTLS_DTLSTRANSPORT_H_
#define _DTLS_DTLSTRANSPORT_H_


#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/srtp.h>
#include <openssl/opensslv.h>


#include "IceConnection.h"
#include "MyIce/IceServer.h"



namespace erizo {

class DtlsTransport : public IceConnectionListener
{
    enum DtlsPacketType{
        UNKNOWN=0,
        STUN ,
        DTLS,
        RTP,
        RTCP
    };
private:
    /* data */
public:
    DtlsTransport(/* args */);
    ~DtlsTransport();
    void OpensslInit();
    void DtlsHandshake(char* buf,int len);
    void SendDtlsMessage();
    DtlsPacketType GetDtlsPacketType(char* buf,int len);
    void SetConnptr(IceConnection *con){conn = con;}
    void CreateFingerprint(X509 *cert, char *fingerprint);
    int createCert(const std::string& pAor, int expireDays, int keyLen, X509*& outCert, EVP_PKEY*& outKey);
    char * GetFingerprint(){return m_fprint;}
public:
    virtual void onPacketReceived(packetPtr packet) override;
    virtual void onCandidate(const CandidateInfo &candidate, IceConnection *conn) override;
    virtual void updateIceState(IceState state, IceConnection *conn) override;

private:
    SSL_CTX* ctx = nullptr;
    SSL* ssl     = nullptr;
    BIO* rbio    = nullptr;
    BIO* wbio    = nullptr;
    unsigned int comp = 0;
    IceConnection * conn = nullptr;
    X509 *m_cert = nullptr;
    EVP_PKEY *m_privatekey = nullptr;
    char m_fprint[100] = {0};

};



}


















#endif