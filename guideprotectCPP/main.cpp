
#include <hiredis/hiredis.h>  
#include <tins/tins.h>
#include <cstdio>
#include <iostream>
#include "SaveVisitLog.h"
#include "UrlProtQuery.h"
#include "WhiteUrl.h"
bool doo(Tins::PDU &some_pdu) {
	// Search for it. If there is no IP PDU in the packet, 
	// the loop goes on
	const Tins::IP &ip = some_pdu.rfind_pdu<Tins::IP>(); // non-const works as well
	std::cout << "Destination address: " << ip.dst_addr() << std::endl;
	// Just one packet please
	return true;
	
}

void test() {
	Tins::SnifferConfiguration config;
	config.set_promisc_mode(true);
	config.set_immediate_mode(true);
	config.set_filter("ip src 192.168.0.100");
	Tins::Sniffer sniffer("eth0", config);
	sniffer.sniff_loop(doo);
}
int  testpcap()
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);
	return(0);
}

int testhiredis()
{
	struct timeval timeout = { 2, 0 };    //2s的超时时间
										  //redisContext是Redis操作对象
	redisContext *pRedisContext = (redisContext*)redisConnectWithTimeout("127.0.0.1", 6379, timeout);
	if ((NULL == pRedisContext) || (pRedisContext->err))
	{
		if (pRedisContext)
		{
			std::cout << "connect error:" << pRedisContext->errstr << std::endl;
		}
		else
		{
			std::cout << "connect error: can't allocate redis context." << std::endl;
		}
		return -1;
	}
	//redisReply是Redis命令回复对象 redis返回的信息保存在redisReply对象中
	redisReply *pRedisReply = (redisReply*)redisCommand(pRedisContext, "INFO");  //执行INFO命令
	std::cout << pRedisReply->str << std::endl;
	//当多条Redis命令使用同一个redisReply对象时 
	//每一次执行完Redis命令后需要清空redisReply 以免对下一次的Redis操作造成影响
	freeReplyObject(pRedisReply);


}

int main() {
	testhiredis();
	printf("hello from guideprotectCPP!1\n");

	//test();
}
