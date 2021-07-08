#include <cstdio>

#include <http/httplib.h>
#include <openssl/ssl.h>
#include <json/json.hpp>

#include "erizo/logger.h"
#include "erizo/MyIce/MyIceConnection.h"
#include "erizo/MyIce/MyLoop.h"



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

int main()
{
    


    printf("iceserver is run\n");
    auto rc = dzlog_init("/home/zn/IceServer/zlog.conf", "iceserver");
    if (rc)
    {
        printf("init failed\n");
    }
    dzlog_info("hello, zlog");

    httplib::Server svr;

    erizo::IceConfig  iceConfig;   
    iceConfig.connection_id = "connection_id_";
    iceConfig.transport_name = "transport_name";
    iceConfig.media_type = erizo::MediaType::VIDEO_TYPE;
    iceConfig.ice_components = 0;
    iceConfig.network_interface = "127.0.0.1";
    std::shared_ptr<erizo::MyIceConnection> ice_ = std::shared_ptr<erizo::MyIceConnection>(new erizo::MyIceConnection(MyLoop::GetLoop(),iceConfig));
    ice_->start();
    char sdpbuffer[2048] = {0};
    sprintf(sdpbuffer,"v=0\no=- 0 0 IN IP4 127.0.0.1\ns=LicodeMCU\nt=0 0\na=group:BUNDLE 0 1\na=msid-semantic: WMS naeY7dlMmr\nm=audio 1 UDP/TLS/RTP/SAVPF 8\nc=IN IP4 0.0.0.0\na=rtcp:1 IN IP4 0.0.0.0\na=candidate:123 1 udp 123 127.0.0.1 %d typ host generation 0\na=ice-ufrag:%s\na=ice-pwd:%s\na=fingerprint:sha-256 4D:70:EC:D5:3E:B3:8C:29:B5:C2:14:66:1A:FA:38:DC:5B:72:17:FF:DD:2C:77:C1:8B:91:9C:64:AF:4E:DE:68\na=setup:actpass\na=sendonly\na=mid:1\na=rtcp-mux\na=rtpmap:8 pcma/8000\nm=video 1 UDP/TLS/RTP/SAVPF 96\nc=IN IP4 0.0.0.0\na=rtcp:1 IN IP4 0.0.0.0\na=candidate:123 1 udp 123 192.168.0.224 %d typ host generation 0\na=ice-ufrag:%s\na=ice-pwd:%s\na=fingerprint:sha-256 4D:70:EC:D5:3E:B3:8C:29:B5:C2:14:66:1A:FA:38:DC:5B:72:17:FF:DD:2C:77:C1:8B:91:9C:64:AF:4E:DE:68\na=setup:actpass\na=sendonly\na=mid:0\na=rtcp-mux\na=rtpmap:96 H264/90000\n",ice_->GetPort(),ice_->getLocalUsername().c_str(),ice_->getLocalPassword().c_str(),ice_->GetPort(),ice_->getLocalUsername().c_str(),ice_->getLocalPassword().c_str());
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
        { dzlog_info(log(req, res).c_str()); });

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


    return 0;
}