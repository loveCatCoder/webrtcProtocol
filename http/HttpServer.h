
#ifndef _HTTPSERVER_H_
#define _HTTPSERVER_H_

#include "http/httplib.h"

class CHttpServer
{
private:
    /* data */
public:
    CHttpServer(/* args */);
    ~CHttpServer();
    void Init();
    void SetSdp(std::string sdp){m_sdp = sdp;};
private:
    httplib::Server m_server;
    std::string m_sdp;
};











#endif
