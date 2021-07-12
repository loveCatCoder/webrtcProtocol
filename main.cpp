#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <memory>

#include <http/httplib.h>
#include <openssl/ssl.h>
#include <json/json.hpp>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "erizo/logger.h"
#include "erizo/MyIce/MyIceConnection.h"
#include "erizo/MyIce/MyLoop.h"
#include "erizo/MyIce/Utils.hpp"
#include "erizo/dtls/DtlsTransport.h"


using namespace httplib;
using namespace std;
// for convenience
using json = nlohmann::json;
string dump_headers(const Headers &headers)
{
    string s;
    char buf[BUFSIZ];

    for (const auto &x : headers)
    {
        snprintf(buf, sizeof(buf), "%s: %s\n", x.first.c_str(), x.second.c_str());
        s += buf;
    }

    return s;
}

string dump_multipart_files(const MultipartFormDataMap &files)
{
    string s;
    char buf[BUFSIZ];

    s += "--------------------------------\n";

    for (const auto &x : files)
    {
        const auto &name = x.first;
        const auto &file = x.second;

        snprintf(buf, sizeof(buf), "name: %s\n", name.c_str());
        s += buf;

        snprintf(buf, sizeof(buf), "filename: %s\n", file.filename.c_str());
        s += buf;

        snprintf(buf, sizeof(buf), "content type: %s\n", file.content_type.c_str());
        s += buf;

        snprintf(buf, sizeof(buf), "text length: %zu\n", file.content.size());
        s += buf;

        s += "----------------\n";
    }

    return s;
}

string log(const Request &req, const Response &res)
{
    string s;
    char buf[BUFSIZ];

    s += "================================\n";

    snprintf(buf, sizeof(buf), "%s %s %s", req.method.c_str(),
             req.version.c_str(), req.path.c_str());
    s += buf;

    string query;
    for (auto it = req.params.begin(); it != req.params.end(); ++it)
    {
        const auto &x = *it;
        snprintf(buf, sizeof(buf), "%c%s=%s",
                 (it == req.params.begin()) ? '?' : '&', x.first.c_str(),
                 x.second.c_str());
        query += buf;
    }
    snprintf(buf, sizeof(buf), "%s\n", query.c_str());
    s += buf;

    s += dump_headers(req.headers);
    s += dump_multipart_files(req.files);

    s += "--------------------------------\n";

    snprintf(buf, sizeof(buf), "%d\n", res.status);
    s += buf;
    s += dump_headers(res.headers);

    return s;
}
#if 1
int main()
{
    
    printf("iceserver is run\n");
    auto rc = dzlog_init("/home/zn/webrtcProtocol/zlog.conf", "iceserver");
    if (rc)
    {
        printf("init failed\n");
    }
    dzlog_info("hello, zlog");

    Utils::Crypto::ClassInit();

    httplib::Server svr;

    std::shared_ptr<erizo::DtlsTransport> dtlsTransport = std::make_shared<erizo::DtlsTransport>();
 
    dtlsTransport->OpensslInit();

    erizo::IceConfig  iceConfig;   
    iceConfig.connection_id = "connection_id_";
    iceConfig.transport_name = "transport_name";
    iceConfig.media_type = erizo::MediaType::VIDEO_TYPE;
    iceConfig.ice_components = 0;
    iceConfig.network_interface = "127.0.0.1";
    std::shared_ptr<erizo::MyIceConnection> ice_ = std::shared_ptr<erizo::MyIceConnection>(new erizo::MyIceConnection(MyLoop::GetLoop(),iceConfig));
    ice_->start();
    ice_->setIceListener(dtlsTransport);
    dtlsTransport->SetConnptr(ice_.get());
    char sdpbuffer[2048] = {0};
    sprintf(sdpbuffer,"v=0\no=- 0 0 IN IP4 127.0.0.1\ns=LicodeMCU\nt=0 0\na=group:BUNDLE 0 1\na=msid-semantic: WMS naeY7dlMmr\nm=audio 1 UDP/TLS/RTP/SAVPF 8\nc=IN IP4 0.0.0.0\na=rtcp:1 IN IP4 0.0.0.0\na=candidate:123 1 udp 123 127.0.0.1 %d typ host generation 0\na=ice-ufrag:%s\na=ice-pwd:%s\na=fingerprint:sha-256 %s\na=setup:actpass\na=sendonly\na=mid:1\na=rtcp-mux\na=rtpmap:8 pcma/8000\nm=video 1 UDP/TLS/RTP/SAVPF 96\nc=IN IP4 0.0.0.0\na=rtcp:1 IN IP4 0.0.0.0\na=candidate:123 1 udp 123 192.168.0.224 %d typ host generation 0\na=ice-ufrag:%s\na=ice-pwd:%s\na=fingerprint:sha-256 %s\na=setup:actpass\na=sendonly\na=mid:0\na=rtcp-mux\na=rtpmap:96 H264/90000\n",ice_->GetPort(),ice_->getLocalUsername().c_str(),ice_->getLocalPassword().c_str(),dtlsTransport->GetFingerprint(),ice_->GetPort(),ice_->getLocalUsername().c_str(),ice_->getLocalPassword().c_str(),dtlsTransport->GetFingerprint());
    svr.Post("/serversdp", [&sdpbuffer](const httplib::Request &, httplib::Response &res)
             {
                 json j;
                 std::string sdp = sdpbuffer;
                 j["sdp"] = sdp;
                 std::string retStr = j.dump();
                 res.set_header("Access-Control-Allow-Origin", "*");
                 res.set_content(retStr, "text/plain");
             });
    svr.Post("/clientsdp", [](const httplib::Request &, httplib::Response &res)
             {
                 res.set_header("Access-Control-Allow-Origin", "*");
                 res.set_content(R"({"code":"200","data":"clientsdp","msg":"ok"})", "text/plain");
                });
    svr.Post("/candidate", [](const httplib::Request &, httplib::Response &res)
                {
                    res.set_header("Access-Control-Allow-Origin", "*");
                    res.set_content(R"({"code":"200","data":"candidate","msg":"ok"})", "text/plain");
                   });
    svr.Options("/(.*)",
                [&](const Request & /*req*/, Response &res)
                {
                    res.set_header("Access-Control-Allow-Methods", " *");
                    res.set_header("Access-Control-Allow-Headers", "*");
                    res.set_header("Access-Control-Allow-Origin", "*");

                    res.set_content(R"({"name":"zn"})", "text/plain");
                });



    svr.set_error_handler([](const httplib::Request & /*req*/, httplib::Response &res)
                          {
                              const char *fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
                              char buf[BUFSIZ];
                              snprintf(buf, sizeof(buf), fmt, res.status);
                              res.set_content(buf, "text/html");
                          });

    svr.set_logger(
        [](const httplib::Request &req, const httplib::Response &res)
        { 
            // dzlog_info(log(req, res).c_str());
        });

    auto port = 7788;

    auto base_dir = "./";

    if (!svr.set_mount_point("/", base_dir))
    {
        dzlog_info("The specified base directory doesn't exist...");
        return 1;
    }

    dzlog_info ("The server started at port:%d ", port);

    svr.listen("localhost", port);

    zlog_fini();

    Utils::Crypto::ClassDestroy();
    return 0;
}
#endif

static struct test_st {
    const char key[17];
    int key_len;
    const unsigned char data[64];
    int data_len;
    const char *digest;
} test[8] = {
    {
        "", 0, "More text test vectors to stuff up EBCDIC machines :-)", 54,
        "e9139d1e6ee064ef8cf514fc7dc83e86",
    },
    {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        16, "Hi There", 8,
        "9294727a3638bb1c13f48ef8158bfc9d",
    },
    {
        "Jefe", 4, "what do ya want for nothing?", 28,
        "750c783e6ab0b503eaa86e310a5db738",
    },
    {
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
        16, {
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd
        }, 50, "56be34521d144c88dbb8c733f0e8b3f6",
    },
    {
        "", 0, "My test data", 12,
        "61afdecb95429ef494d61fdee15990cabf0826fc"
    },
    {
        "", 0, "My test data", 12,
        "2274b195d90ce8e03406f4b526a47e0787a88a65479938f1a5baa3ce0f079776"
    },
    {
        "123456", 6, "My test data", 12,
        "bab53058ae861a7f191abe2d0145cbb123776a6369ee3f9d79ce455667e411dd"
    },
    {
        "12345", 5, "My test data again", 18,
        "a12396ceddd2a85f4c656bc1e0aa50c78cffde3e"
    }
};


// int main()
// {
//     auto rc = dzlog_init("/home/zn/webrtcProtocol/zlog.conf", "iceserver");
//     if (rc)
//     {
//         printf("init failed\n");
//     }
//     dzlog_info("hello, zlog");
//     char *p;
//     HMAC_CTX *ctx = NULL;
//     unsigned char buf[EVP_MAX_MD_SIZE];
//     unsigned int len;
//     int ret = 0;
//     char key[25] = "g23xv58l2fu6atjytvg6065i";
//     ctx = HMAC_CTX_new();
//     // HMAC_CTX_reset(ctx);
//     HMAC_Init_ex(ctx, key, 24, EVP_sha1(), NULL);
//     // HMAC_Init_ex(ctx, test[4].key, test[4].key_len, EVP_sha1(), NULL);
//     HMAC_Update(ctx, test[4].data, test[4].data_len);
//     HMAC_Final(ctx, buf, &len);

//     HMAC_CTX_free(ctx);
//     dzlog_info("buf:%s",buf);
// }