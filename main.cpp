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
#include "erizo/WebrtcConn.h"

#include "http/HttpServer.h"

using namespace httplib;
using namespace std;
// for convenience
using json = nlohmann::json;

void ZlogInit()
{
    auto rc = dzlog_init("/home/zn/webrtcProtocol/zlog.conf", "iceserver");
    if (rc)
    {
        printf("init failed\n");
    }
    dzlog_info("hello, zlog");
}
void ZlogDestroy()
{
    zlog_fini();
}

int main()
{
    ZlogInit();
    Utils::Crypto::ClassInit();
    std::shared_ptr<CWebrtcConn> rtcConn= std::make_shared<CWebrtcConn>();
    rtcConn->Init();

    CHttpServer server;
    server.SetSdp(rtcConn->GetSdp());
    server.Init();

    ZlogDestroy();
    Utils::Crypto::ClassDestroy();
    return 0;
}