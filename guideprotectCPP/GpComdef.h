#pragma once
#include <tins/tins.h>
#include <string.h>

//value for m_handle_result
#define  URL_HANDLE_RESULT_NONE 0 
#define  URL_HANDLE_RESULT_BLOCK 1 
#define  URL_HANDLE_RESULT_REDIRECT 2 

class CHttpGetInfo
{

public:
	std::string m_fullurl;
	std::string m_host;
	std::string m_req_url;

	std::string m_redirect_url;
	std::string m_user_agent;
	std::string m_referer;
	int		m_handle_result;
	uint32_t m_src_ip;
	uint32_t m_dst_ip;
	int m_src_port;
	int m_dst_port;
	const Tins::IP	*m_pdu_ip;
	const Tins::TCP	*m_pdu_tcp;
	const Tins::RawPDU	*m_pdu_raw;

public:
	CHttpGetInfo() {};
	~CHttpGetInfo() {};
protected:

private:
};


typedef void(*HttpInfoCallback)(CHttpGetInfo *pInfo);