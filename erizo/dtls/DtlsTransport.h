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


#include "MyIce/MyIceConnection.h"
#include "MyIce/IceServer.h"
#include "SrtpChannel.h"



#define SRTP_MASTER_KEY_LEN 30

namespace erizo {


const int SRTP_MASTER_KEY_KEY_LEN = 16;
const int SRTP_MASTER_KEY_SALT_LEN = 14;
static const int DTLS_MTU = 1472;


class SrtpSessionKeys {
 public:
  SrtpSessionKeys() {
    clientMasterKey = new unsigned char[SRTP_MASTER_KEY_KEY_LEN];
    clientMasterKeyLen = 0;
    clientMasterSalt = new unsigned char[SRTP_MASTER_KEY_SALT_LEN];
    clientMasterSaltLen = 0;
    serverMasterKey = new unsigned char[SRTP_MASTER_KEY_KEY_LEN];
    serverMasterKeyLen = 0;
    serverMasterSalt = new unsigned char[SRTP_MASTER_KEY_SALT_LEN];
    serverMasterSaltLen = 0;
  }
  ~SrtpSessionKeys() {
    if (clientMasterKey) {
      delete[] clientMasterKey; clientMasterKey = NULL;
    }
    if (serverMasterKey) {
      delete[] serverMasterKey; serverMasterKey = NULL;
    }
    if (clientMasterSalt) {
      delete[] clientMasterSalt; clientMasterSalt = NULL;
    }
    if (serverMasterSalt) {
      delete[] serverMasterSalt; serverMasterSalt = NULL;
    }
  }
  unsigned char *clientMasterKey;
  int clientMasterKeyLen;
  unsigned char *serverMasterKey;
  int serverMasterKeyLen;
  unsigned char *clientMasterSalt;
  int clientMasterSaltLen;
  unsigned char *serverMasterSalt;
  int serverMasterSaltLen;
};


class TransportListener {
 public:
  virtual void onCandidate(const CandidateInfo &candidate, IceConnection *conn) = 0;
};

class DtlsTransport :  public IceConnectionListener,
                        public std::enable_shared_from_this<DtlsTransport>                     
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
    void Init();
    void DtlsHandshake(char* buf,int len);
    void HanshakeCompleted();
    void SendDtlsMessage();
    DtlsPacketType GetDtlsPacketType(char* buf,int len);
    void SetConnptr(IceConnection *con){conn = con;}
    void CreateFingerprint(X509 *cert, char *fingerprint);
    int createCert(const std::string& pAor, int expireDays, int keyLen, X509*& outCert, EVP_PKEY*& outKey);

    std::string ComputeRemoteFingerprint(X509* cert);
    std::string GetLocalFingerprint();
    std::string GetRemoteFingerprint();
    bool CheckRemoteFingerprint(std::string sdpFprint);


    const std::string& getLocalUsername() {return m_ice->getLocalUsername();};
    const std::string& getLocalPassword() {return m_ice->getLocalPassword();};

    void SetTransportListener(std::weak_ptr<TransportListener> listener){m_listener = listener;};

    SrtpSessionKeys* GetSrtpSessionKeys();
public:
    virtual void onPacketReceived(packetPtr packet) override;
    virtual void onCandidate(const CandidateInfo &candidate, IceConnection *conn) override;
    virtual void updateIceState(IceState state, IceConnection *conn) override;
private:
    void InitOpenssl();
    void InitIce();
private:
    std::shared_ptr<erizo::IceConnection> m_ice;
    std::weak_ptr<erizo::TransportListener> m_listener;
    SSL_CTX* ctx = nullptr;
    SSL* ssl     = nullptr;
    BIO* rbio    = nullptr;
    BIO* wbio    = nullptr;
    unsigned int comp = 0;
    IceConnection * conn = nullptr;
    X509 *m_cert = nullptr;
    EVP_PKEY *m_privatekey = nullptr;
    char m_fprint[100] = {0};
    SrtpSessionKeys* m_keys;

    SrtpChannel* m_srtp = nullptr;
};



}


















#endif