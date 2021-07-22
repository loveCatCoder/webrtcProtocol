#ifndef  _ERIZO_ICESERVER_H_
#define  _ERIZO_ICESERVER_H_

#include <functional>
#include <memory>

#include "net/SocketUtil.h"
#include "StunPacket.hpp"
#include "logger.h"

class IceServer
{
public:
	enum class IceState
	{
		NEW = 1,
		CONNECTED,
		COMPLETED,
		DISCONNECTED
	};
	using FSendCb = std::function<void(char* buf, int len, struct sockaddr_in* remoteAddr)>;
    using Ptr =  std::shared_ptr<IceServer> ;
	IceServer();
	IceServer(const std::string& usernameFragment, const std::string& password);
	~IceServer();

	const std::string& GetUsernameFragment() const;
	const std::string& GetPassword() const;
	void SetUsernameFragment(const std::string& usernameFragment);
	void SetPassword(const std::string& password);

	IceState GetState() const;
	void ProcessStunPacket(RTC::StunPacket* packet, struct sockaddr_in* remoteAddr);
	void HandleTuple(struct sockaddr_in* remoteAddr, bool hasUseCandidate);
	
	void SetSendCB(FSendCb send_cb);
	void SetIceServerCompletedCB(std::function<void()> cb) ;
	struct sockaddr_in* GetSelectAddr() ;
private:
	FSendCb m_send_cb;
	std::function<void()> m_IceServerCompletedCB;
	std::string usernameFragment;
	std::string password;
	std::string oldUsernameFragment;
	std::string oldPassword;
	IceState state={ IceState::NEW };
	struct sockaddr_in m_remoteAddr;

};

#endif