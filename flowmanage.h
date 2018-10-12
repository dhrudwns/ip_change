#ifndef FLOWMANAGE_H
#define FLOWMANAGE_H
#include <stdint.h>

class flowmanage
{
public:
    uint32_t ip_src;
    uint32_t ip_dst;
    void init(const uint32_t &ip_src, const uint32_t &ip_dst)
    {
        this->ip_src = ip_src;
        this->ip_dst = ip_dst;
    }
    void reverse(flowmanage flow)
    {
	    this->ip_src = flow.ip_dst;
	    this->ip_dst = flow.ip_src;
    }

    bool operator < (const flowmanage &flow) const {
                          if(this->ip_src < flow.ip_src) return true;
                          if(this->ip_src > flow.ip_src) return false;
                          if(this->ip_dst < flow.ip_dst) return true;
                          return false;
                  }
};
#endif // FLOW_H
