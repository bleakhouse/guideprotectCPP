#include "HttpParsr.h"
#include <iostream>
#include <sstream>


#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>

// trim from start
static inline std::string &ltrim(std::string &s) {
	s.erase(s.begin(), std::find_if(s.begin(), s.end(),
		std::not1(std::ptr_fun<int, int>(std::isspace))));
	return s;
}

// trim from end
static inline std::string &rtrim(std::string &s) {
	s.erase(std::find_if(s.rbegin(), s.rend(),
		std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
	return s;
}

// trim from both ends
static inline std::string &trim(std::string s) {
	return ltrim(rtrim(s));
}


bool CHttpParsr::parse(CHttpGetInfo *pinfo)
{
	std::cout << "im in " << __FUNCTION__ << std::endl;

	std::map<std::string, std::string> m;

	std::istringstream resp(((char*)(pinfo->m_pdu_raw->payload().data())));
	std::string header;
	std::string::size_type index;
	bool isfirst = true;

	while (std::getline(resp, header) && header != "\r") 
	{
		if (isfirst)
		{
			int starthttp = header.find("HTTP/1");
			pinfo->m_req_url = header.substr(4, starthttp-5);
			isfirst = false;
			continue;
		}
		index = header.find(':', 0);
		if (index != std::string::npos) 
		{
			int vstart = index + 1 + 1;
			if (strcmp(header.substr(0, index).c_str(), "Host")==0)
			{
				pinfo->m_host = header.substr(vstart, header.length() - vstart - 1);
			}
			else if (strcmp(header.substr(0, index).c_str(), "User-Agent") == 0)
			{
				pinfo->m_user_agent = header.substr(vstart, header.length() - vstart - 1);
			}
			else if (strcmp(header.substr(0, index).c_str(), "Referer") == 0)
			{
				pinfo->m_referer = header.substr(vstart, header.length() - vstart - 1);
			}

			//m.insert(std::make_pair((header.substr(0, index)), (header.substr(vstart, header.length()- vstart-1))));
		}
	}

	return true;

}

CHttpParsr::CHttpParsr()
{

}


CHttpParsr::~CHttpParsr()
{
}
