class flowmanage
{
public:
	uint32_t ip_src;
	uint32_t ip_dst;
	//uint16_t ip_sport;
	//uint16_t ip_dport;
public:
	void init(const uint32_t &ip_src, const uint32_t &ip_dst)
	{
	this->ip_src = ip_src;
	this->ip_dst = ip_dst;
	//this->ip_sport = ip_sport;
	//this->ip_dport = ip_dport;
	}
	void reverse(const flowmanage &original)
	{
		ip_src = original.ip_dst;
		ip_dst = original.ip_src;
		//ip_sport = original.ip_dport;
		//ip_dport = original.ip_sport;
	}
	bool operator < (const flowmanage &change) const
	{
		if(this->ip_src < change.ip_dst) return true;
		if(this->ip_src > change.ip_dst) return false;
		if(this->ip_dst < change.ip_src) return true;
		return false;
		//if(this->ip_sport < change.ip_dport) return true;
		//if(this->ip_sport > change.ip_dport) return false;
		//if(this->ip_dport < change.ip_sport) return true;
		//if(this->ip_dport > change.ip_sport) return false;
	}

};
