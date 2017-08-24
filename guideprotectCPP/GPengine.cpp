#include "GPengine.h"




bool CGPengine::start(HttpInfoCallback pCallback)
{
	m_http_info_callback = pCallback;
	if (m_http_info_callback==nullptr)
	{
		return false;
	}
	
	return m_cyber_intercept.start(m_http_info_callback);

}

CGPengine::CGPengine()
{
}


CGPengine::~CGPengine()
{
}
