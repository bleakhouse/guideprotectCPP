#pragma once
#include <tins/tins.h>
#include "CyberInterceptor.h"
#include "GpComdef.h"


class CGPengine
{
	
	CCyberInterceptor m_cyber_intercept;
	HttpInfoCallback m_http_info_callback;
protected:

public:
	bool start(HttpInfoCallback pCallback);
	
	CGPengine();
	~CGPengine();
};

