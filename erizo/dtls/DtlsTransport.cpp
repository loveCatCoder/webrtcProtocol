

#include <assert.h>
#include <sstream>
#include <string>

#include "DtlsTransport.h"
#include "MyIce/MyLoop.h"

namespace erizo
{


  static char *Base64Encode(const char* input, int length, bool with_new_line)
    {
        BIO* bmem = NULL;
        BIO* b64 = NULL;
        BUF_MEM* bptr = NULL;
        b64 = BIO_new(BIO_f_base64());
        if (!with_new_line)
        {
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        }
        bmem = BIO_new(BIO_s_mem());
        b64 = BIO_push(b64, bmem);
        BIO_write(b64, input, length);
        if( BIO_flush(b64) );
        BIO_get_mem_ptr(b64, &bptr);
        char * buff = (char *)malloc(bptr->length + 1);
        memcpy(buff, bptr->data, bptr->length);
        buff[bptr->length] = 0;
        BIO_free_all(b64);
        return buff;
    }


    DtlsTransport::DtlsTransport(/* args */)
    {
        m_srtp = new SrtpChannel();
    }

    DtlsTransport::~DtlsTransport()
    {
        delete m_srtp;
    }

    void DtlsTransport::Init()
    {
        InitOpenssl();
        InitIce();
    }

    int DtlsTransport::createCert(const std::string &pAor, int expireDays, int keyLen, X509 *&outCert, EVP_PKEY *&outKey)
    { // NOLINT

        dzlog_info("Generating new user cert for:%s", pAor.c_str());
        std::string aor = "sip:" + pAor;

        // Make sure that necessary algorithms exist:
        assert(EVP_sha1());
        //生成存储非对称密钥的数据结构
        EVP_PKEY *privkey = EVP_PKEY_new();
        assert(privkey);
        //创建rsa密钥并设置到privkey
        RSA *rsa = RSA_new();

        BIGNUM *exponent = BN_new();
        BN_set_word(exponent, 0x10001);

        RSA_generate_key_ex(rsa, 1024, exponent, NULL);

        // RSA* rsa = RSA_generate_key(keyLen, RSA_F4, NULL, NULL);
        assert(rsa); // couldn't make key pair

        int ret = EVP_PKEY_set1_RSA(privkey, rsa);
        assert(ret);

        X509 *cert = X509_new();
        assert(cert);

        X509_NAME *subject = X509_NAME_new();
        X509_EXTENSION *ext = X509_EXTENSION_new();

        // set version to X509v3 (starts from 0)
        // X509_set_version(cert, 0L);

        int serial = 222123128; // get an int worth of randomness
        assert(sizeof(int) == 4);
        //设置serial到cert的序列号中
        ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

        //    ret = X509_NAME_add_entry_by_txt( subject, "O",  MBSTRING_ASC,
        //                                      (unsigned char *) domain.data(), domain.size(),
        //                                      -1, 0);
        assert(ret);
        ret = X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (unsigned char *)aor.data(), aor.size(), -1, 0);
        assert(ret);

        ret = X509_set_issuer_name(cert, subject);
        assert(ret);
        ret = X509_set_subject_name(cert, subject);
        assert(ret);

        const long duration = 60 * 60 * 24 * expireDays; // NOLINT
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), duration);

        ret = X509_set_pubkey(cert, privkey);
        assert(ret);

        std::string subjectAltNameStr = std::string("URI:sip:") + aor + std::string(",URI:im:") + aor + std::string(",URI:pres:") + aor;
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, (char *)subjectAltNameStr.c_str()); // NOLINT
        //   X509_add_ext( cert, ext, -1);
        X509_EXTENSION_free(ext);

        static char CA_FALSE[] = "CA:FALSE";
        ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, CA_FALSE);
        ret = X509_add_ext(cert, ext, -1);
        assert(ret);
        X509_EXTENSION_free(ext);

        // TODO(javier) add extensions NID_subject_key_identifier and NID_authority_key_identifier

        ret = X509_sign(cert, privkey, EVP_sha1());
        assert(ret);

        outCert = cert;
        outKey = privkey;
        return ret;
    }
    
   

    std::string DtlsTransport::ComputeRemoteFingerprint(X509 *cert)
    {
        unsigned char md[EVP_MAX_MD_SIZE];
        char fingerprint[EVP_MAX_MD_SIZE*2] = {0};
        char *fingerprintIndex = &fingerprint[0];
        int r;
        unsigned int i, n;

        // r = X509_digest(cert, EVP_sha1(), md, &n);
        r = X509_digest(cert, EVP_sha256(), md, &n);
        // TODO(javier) - is sha1 vs sha256 supposed to come from DTLS handshake?
        // fixing to to SHA-256 for compatibility with current web-rtc implementations
        assert(r == 1);

        for (i = 0; i < n; i++)
        {
            sprintf(fingerprintIndex, "%02X", md[i]); // NOLINT
            fingerprintIndex += 2;

            if (i < (n - 1))
                *fingerprintIndex++ = ':';
            else
                *fingerprintIndex++ = 0;
        }

        return std::string(fingerprint);
    }

    std::string DtlsTransport::GetLocalFingerprint()
    {
        std::string print = m_fprint;
        return print;
    }
    
    std::string DtlsTransport::GetRemoteFingerprint() 
    {
        X509* x = SSL_get_peer_certificate(ssl);
        if (!x) {  // No certificate
            return "";
        }

        std::string print = ComputeRemoteFingerprint(x);
        X509_free(x);
        return print;
    }
    
    bool DtlsTransport::CheckRemoteFingerprint(std::string sdpFprint) 
    {
        std::string dtlsFprint  = GetRemoteFingerprint();
        if(sdpFprint == dtlsFprint)
        {
            return true;
        }
        return false;
    }

    SrtpSessionKeys *DtlsTransport::GetSrtpSessionKeys()
    {
        // TODO(pedro): probably an exception candidate
        // assert(mHandshakeCompleted);

        SrtpSessionKeys *keys = new SrtpSessionKeys();

        unsigned char material[SRTP_MASTER_KEY_LEN << 1];
        if (!SSL_export_keying_material(ssl, material, sizeof(material), "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0))
        {
            return keys;
        }

        size_t offset = 0;

        memcpy(keys->clientMasterKey, &material[offset], SRTP_MASTER_KEY_KEY_LEN);
        offset += SRTP_MASTER_KEY_KEY_LEN;
        memcpy(keys->serverMasterKey, &material[offset], SRTP_MASTER_KEY_KEY_LEN);
        offset += SRTP_MASTER_KEY_KEY_LEN;
        memcpy(keys->clientMasterSalt, &material[offset], SRTP_MASTER_KEY_SALT_LEN);
        offset += SRTP_MASTER_KEY_SALT_LEN;
        memcpy(keys->serverMasterSalt, &material[offset], SRTP_MASTER_KEY_SALT_LEN);
        offset += SRTP_MASTER_KEY_SALT_LEN;
        keys->clientMasterKeyLen = SRTP_MASTER_KEY_KEY_LEN;
        keys->serverMasterKeyLen = SRTP_MASTER_KEY_KEY_LEN;
        keys->clientMasterSaltLen = SRTP_MASTER_KEY_SALT_LEN;
        keys->serverMasterSaltLen = SRTP_MASTER_KEY_SALT_LEN;

        ELOG_DEBUG("client key:%s", keys->clientMasterKey);
        ELOG_DEBUG("server key:%s", keys->serverMasterKey);
        ELOG_DEBUG("client salt:%s", keys->clientMasterSalt);
        ELOG_DEBUG("server salt:%s", keys->serverMasterSalt);
        return keys;
    }

    void DtlsTransport::DtlsHandshake(char *buf, int len)
    {
        // Why must reset?
        BIO_reset(rbio);
        BIO_reset(wbio);
        BIO_write(rbio, buf, len);

        int r0 = SSL_do_handshake(ssl);
        int r1 = SSL_get_error(ssl, r0);
        if (r1 == SSL_ERROR_NONE)
        {
            HanshakeCompleted();
        }
        // Fatal SSL error, for example, no available suite when peer is DTLS 1.0 while we are DTLS 1.2.
        if (r0 < 0 && (r1 != SSL_ERROR_NONE && r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE))
        {
            dzlog_info("handshake r0=%d,r1=%d", r0, r1);
            exit(-1);
        }
    }

    void DtlsTransport::SendDtlsMessage()
    {
        char *data = nullptr;
        int size = BIO_get_mem_data(wbio, &data);

        m_ice->sendData(comp, data, size);
        dzlog_info("size=%d", size);
    }

    DtlsTransport::DtlsPacketType DtlsTransport::GetDtlsPacketType(char *buf, int len)
    {
        if ((buf[0] == 0) || (buf[0] == 1))
            return DtlsPacketType::STUN;
        if ((buf[0] >= 128) && (buf[0] <= 191))
            return DtlsPacketType::RTP;
        if ((buf[0] >= 20) && (buf[0] <= 64))
            return DtlsPacketType::DTLS;

        return DtlsPacketType::UNKNOWN;
    }

    void DtlsTransport::CreateFingerprint(X509 *cert, char *fingerprint)
    {
        unsigned char md[EVP_MAX_MD_SIZE];
        int r;
        unsigned int i, n;

        // r = X509_digest(cert, EVP_sha1(), md, &n);
        r = X509_digest(cert, EVP_sha256(), md, &n);
        // TODO(javier) - is sha1 vs sha256 supposed to come from DTLS handshake?
        // fixing to to SHA-256 for compatibility with current web-rtc implementations
        assert(r == 1);

        for (i = 0; i < n; i++)
        {
            sprintf(fingerprint, "%02X", md[i]); // NOLINT
            fingerprint += 2;

            if (i < (n - 1))
                *fingerprint++ = ':';
            else
                *fingerprint++ = 0;
        }
    }

    void DtlsTransport::onPacketReceived(packetPtr packet)
    {
        DtlsPacketType type = GetDtlsPacketType(packet->data, packet->length);
        if (type == DtlsPacketType::DTLS)
        {
            comp = packet->comp;
            DtlsTransport::DtlsHandshake(packet->data, packet->length);
            SendDtlsMessage();
        }
    }

    void DtlsTransport::onCandidate(const CandidateInfo &candidate, IceConnection *conn)
    {
        if (auto listener = m_listener.lock())
        {
            listener->onCandidate(candidate, conn);
            dzlog_info("DtlsTransport::onCandidate:%s", candidate.hostAddress.c_str());
        }
    }

    void DtlsTransport::HanshakeCompleted()
    {

        SRTP_PROTECTION_PROFILE *srtp_profile;
        std::string fprint = GetRemoteFingerprint();
        if (fprint != "")
        {
            ELOG_INFO("Remote fingerprint == %s", fprint.c_str());

            bool check = CheckRemoteFingerprint(fprint);
            ELOG_DEBUG("Fingerprint check == %d", check);

            SrtpSessionKeys *keys = GetSrtpSessionKeys();

            unsigned char *cKey = (unsigned char *)malloc(keys->clientMasterKeyLen + keys->clientMasterSaltLen);
            unsigned char *sKey = (unsigned char *)malloc(keys->serverMasterKeyLen + keys->serverMasterSaltLen);

            memcpy(cKey, keys->clientMasterKey, keys->clientMasterKeyLen);
            memcpy(cKey + keys->clientMasterKeyLen, keys->clientMasterSalt, keys->clientMasterSaltLen);

            memcpy(sKey, keys->serverMasterKey, keys->serverMasterKeyLen);
            memcpy(sKey + keys->serverMasterKeyLen, keys->serverMasterSalt, keys->serverMasterSaltLen);



            char *temp = Base64Encode((const char *)cKey, keys->clientMasterKeyLen + keys->clientMasterSaltLen, false);
            std::string clientKey = temp;
            free(temp);
            temp = NULL;
            temp = Base64Encode((const char *)sKey, keys->serverMasterKeyLen + keys->serverMasterSaltLen, false);
            std::string serverKey = temp;
            free(temp);
            temp = NULL;

            ELOG_DEBUG("ClientKey: %s", clientKey.c_str());
            ELOG_DEBUG("ServerKey: %s", serverKey.c_str());

            free(cKey);
            free(sKey);
            delete keys;

            srtp_profile = SSL_get_selected_srtp_profile(ssl);

            if (srtp_profile)
            {
                ELOG_DEBUG("SRTP Extension negotiated profile=%s", srtp_profile->name);
            }

            
            clientKey.swap(serverKey);
            
            m_srtp->setRtpParams(clientKey, serverKey);
        }
        else
        {
            ELOG_DEBUG("Peer did not authenticate");
        }
    }

    void DtlsTransport::updateIceState(IceState state, IceConnection *conn)
    {
        dzlog_info("IceState:%d", state);
    }

    void DtlsTransport::InitOpenssl()
    {

        SSL_library_init();

        createCert("sip:licode@lynckia.com", 365, 1024, m_cert, m_privatekey);

        CreateFingerprint(m_cert, m_fprint);
        dzlog_info("m_fprint:%s", m_fprint);
        ctx = SSL_CTX_new(DTLS_server_method());

        assert(SSL_CTX_use_certificate(ctx, m_cert) == 1);
        assert(SSL_CTX_use_PrivateKey(ctx, m_privatekey) == 1);
        SSL_CTX_set_default_verify_file(ctx);

        SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
        int r = SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AES128_CM_SHA1_80");
        assert(r == 0);

        ssl = SSL_new(ctx);

        SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
        SSL_set_mtu(ssl, 1500);
        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl, rbio, wbio);

        // Dtls setup passive, as server role.
        SSL_set_accept_state(ssl);
    }

    void DtlsTransport::InitIce()
    {
        erizo::IceConfig iceConfig;
        iceConfig.connection_id = "connection_id_";
        iceConfig.transport_name = "transport_name";
        iceConfig.media_type = erizo::MediaType::VIDEO_TYPE;
        iceConfig.ice_components = 0;
        iceConfig.network_interface = "127.0.0.1";
        m_ice = std::make_shared<MyIceConnection>(MyLoop::GetLoop(), iceConfig);
        m_ice->setIceListener(shared_from_this());
        m_ice->start();
    }

}
