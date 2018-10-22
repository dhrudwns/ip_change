#include <iostream>
#include <stdio.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <set>
#include <errno.h>
#include <netinet/in_systm.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "flowmanage.h"
#include "header.h"
#define LIBNET_LIL_ENDIAN 1
#define IPPROTO_TCP 6


using namespace std;

static uint32_t new_data_len, before_ip, after_ip, flag;
static uint8_t* new_data;
static set<flowmanage> flow_check;

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
            printf("%02x ", buf[i]);
    }
}

#pragma pack(push,1)
struct Pseudoheader{
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t TCPLen;
};
#pragma pack(pop)

uint16_t calculate(uint16_t* data, int dataLen)
{
    uint32_t sum=0;
    while(dataLen>1){
        sum+=ntohs(*data++);
        dataLen-=2;
    }
    if(dataLen==1){
        sum+=ntohs((uint8_t)*data);
    }
    //sum = (sum >> 16) + (sum & 0xffff);
    sum = (sum >> 16) + (sum & 0xffff);
    return (uint16_t)sum;
}

uint16_t calTCPChecksum(uint8_t *data,int dataLen)
{
    struct Pseudoheader pseudoheader;

    //init Pseudoheader
    struct ipv4_hdr *iph=(struct ipv4_hdr*)data;
    struct tcp_hdr *tcph=(struct tcp_hdr*)(data+iph->ip_hl*4);

    memcpy(&pseudoheader.srcIP,&iph->ip_src,sizeof(pseudoheader.srcIP));
    memcpy(&pseudoheader.destIP,&iph->ip_dst,sizeof(pseudoheader.destIP));
    pseudoheader.protocol=iph->ip_p;
    pseudoheader.TCPLen=htons(dataLen-(iph->ip_hl*4));

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    tcph->th_sum=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)tcph,ntohs(pseudoheader.TCPLen));

    uint16_t checksum;
    uint32_t temp;
    temp = pseudoResult+tcpHeaderResult;
    //temp = (temp >> 16) + (temp & 0xffff);
    temp = (temp >> 16) + (temp & 0xffff);
    checksum = ntohs(~temp);
    tcph->th_sum=checksum;

    return checksum;
}

uint16_t calIPChecksum(uint8_t *data)
{
    struct ipv4_hdr *iph=(struct ipv4_hdr*)data;
    iph->ip_sum=0;

    uint16_t checksum=calculate((uint16_t*)iph,iph->ip_hl*4);
    iph->ip_sum = ntohs(~checksum);
    return checksum;
}

static uint32_t print_pkt (struct nfq_data *tb)
{
    uint32_t id = 0;
    uint32_t flag = 0;
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t ret;
    uint8_t *data;

    ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
            id = ntohl(ph->packet_id);
        }

    ret = nfq_get_payload(tb, &data);
    if(ret >= 0) {
        new_data = data;
        flag = 0;
        struct ipv4_hdr* iph = (struct ipv4_hdr *) data;
        if(iph->ip_p == IPPROTO_TCP){
            struct tcp_hdr* tcph = (struct tcp_hdr *)((uint8_t*)iph+iph->ip_hl*4);
            flowmanage flow;
            set<flowmanage>::iterator iter, r_iter;
            flow.init(iph->ip_src, iph->ip_dst);
            if(iph->ip_dst == before_ip){
                flow.init(iph->ip_src, after_ip);
                flow_check.insert(flow);
            }
            
            iter = flow_check.find(flow);
            flow.reverse(flow);
            r_iter = flow_check.find(flow);
            
            if(iter!=flow_check.end())
                {
                    memcpy(&iph->ip_dst, &after_ip, sizeof(iph->ip_dst));
                    calIPChecksum(new_data);
                    calTCPChecksum(new_data, ret);
                    new_data_len = ret;
                    flag = 1;
                }
            else if(r_iter!=flow_check.end())
                {
                    memcpy(&iph->ip_src, &before_ip, sizeof(iph->ip_src));
                    calIPChecksum(new_data);
                    calTCPChecksum(new_data ,ret);
                    new_data_len = ret;
                    flag = 1;
                }
             else flag = 0; 
        }
        return id;
    }
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);

    if(flag == 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    else {
    printf("Changed!!\n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, new_data_len, new_data);
    }
}
int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if(argc != 3){
    printf("use : ./ip_change <before ip> <after ip>\n");
    return 0;
    }

    before_ip = inet_addr(argv[1]);
    after_ip = inet_addr(argv[2]);

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        printf("error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        printf("error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        printf("error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");

    qh = nfq_create_queue(h,  0, &cb, NULL);					// Queue create
    if (!qh) {
        printf("error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf("can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
 //           printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
