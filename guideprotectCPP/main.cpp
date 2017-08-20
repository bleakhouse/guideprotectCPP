
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
	struct timeval timeout = { 2, 0 };    //2s�ĳ�ʱʱ��
										  //redisContext��Redis��������
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
	//redisReply��Redis����ظ����� redis���ص���Ϣ������redisReply������
	redisReply *pRedisReply = (redisReply*)redisCommand(pRedisContext, "INFO");  //ִ��INFO����
	std::cout << pRedisReply->str << std::endl;
	//������Redis����ʹ��ͬһ��redisReply����ʱ 
	//ÿһ��ִ����Redis�������Ҫ���redisReply �������һ�ε�Redis�������Ӱ��
	freeReplyObject(pRedisReply);


}

int main() {
	testhiredis();
	printf("hello from guideprotectCPP!1\n");

	//test();
}
