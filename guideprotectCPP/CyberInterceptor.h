#pragma once
#include <tins/tins.h>
#include <string.h>
#include "HttpParsr.h"
#include "GpComdef.h"

class CCyberInterceptor
{
	Tins::SnifferConfiguration m_tins_config;
	std::string		m_str_sniffer_eth;
	std::string		m_str_inject_eth;
	std::string		m_str_filter;

	CHttpParsr		m_http_parser;

	HttpInfoCallback	m_callback;

protected:
	bool init();
	bool readcfg();
	bool redirect_url(CHttpGetInfo *pinfo);


public:
	bool start(HttpInfoCallback next);
	bool handle_http(CHttpGetInfo *pinfo);
	CCyberInterceptor();
	~CCyberInterceptor();
};

