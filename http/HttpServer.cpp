

#include <json/json.hpp>

#include "HttpServer.h"
#include "erizo/logger.h"

using namespace httplib;
using namespace std;
using json = nlohmann::json;

CHttpServer::CHttpServer(/* args */)
{
}

CHttpServer::~CHttpServer()
{
}

void CHttpServer::Init()
{
    m_server.Post("/serversdp", [&](const httplib::Request &, httplib::Response &res)
                  {
                      json j;
                      std::string sdp = m_sdp;
                      j["sdp"] = sdp;
                      std::string retStr = j.dump();
                      res.set_header("Access-Control-Allow-Origin", "*");
                      res.set_content(retStr, "text/plain");
                  });
    m_server.Post("/clientsdp", [](const httplib::Request &, httplib::Response &res)
                  {
                      res.set_header("Access-Control-Allow-Origin", "*");
                      res.set_content(R"({"code":"200","data":"clientsdp","msg":"ok"})", "text/plain");
                  });
    m_server.Post("/candidate", [](const httplib::Request &, httplib::Response &res)
                  {
                      res.set_header("Access-Control-Allow-Origin", "*");
                      res.set_content(R"({"code":"200","data":"candidate","msg":"ok"})", "text/plain");
                  });
    m_server.Options("/(.*)",
                     [&](const Request & /*req*/, Response &res)
                     {
                         res.set_header("Access-Control-Allow-Methods", " *");
                         res.set_header("Access-Control-Allow-Headers", "*");
                         res.set_header("Access-Control-Allow-Origin", "*");

                         res.set_content(R"({"name":"zn"})", "text/plain");
                     });

    m_server.set_error_handler([](const httplib::Request & /*req*/, httplib::Response &res)
                               {
                                   const char *fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
                                   char buf[BUFSIZ];
                                   snprintf(buf, sizeof(buf), fmt, res.status);
                                   res.set_content(buf, "text/html");
                               });

    m_server.set_logger(
        [](const httplib::Request &req, const httplib::Response &res)
        {
            // dzlog_info(log(req, res).c_str());
        });

    auto port = 7788;
    dzlog_info("The server started at port:%d ", port);
    m_server.listen("localhost", port);
}
