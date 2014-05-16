#ifndef _PANALY_H_
#define _PANALY_H_

#include "structure.h"

#define PDU_HASH_ACC	128
#define MSID_HASH_ACC	4096
#define RADIUS_HASH_ACC	4096
#define HASH(i,j)	(i)&(j-1)

#define GRE_FLAG	0x2f
#define UDP_FLAG	0x11
#define IPV4	0x2100
#define LCP	0x21c0
#define PAP	0x23c0
#define CHAP	0x23c2
#define IPCP	0x2180

#define PPP_FLAG	0x7e
#define ESCAPE_OCTET	0x7d

//ethernet header
struct etherhdr{
	u_char dst_mac[6];
	u_char src_mac[6];
	_Int16 type;
};

//802.1q virtual lan
struct virlanhdr{
	_Int16 pri_cfi_id;
	_Int16 type;
};

//ipv4 header
struct ipv4hdr{
	u_char ver_len;
	u_char service;
	_Int16 total_len;
	_Int16 id;
	_Int16 flag_offset;
	u_char ttl;
	u_char proto;
	_Int16 checksum;
	_Int32 src;
	_Int32 dst;
};

//gre header
struct grehdr{
	_Int16 flag_ver;
	_Int16 prot;
	_Int32 key;
	_Int32 seq;
};

struct framehdr{
	struct etherhdr *eth;
	struct virlanhdr *vlan;
	struct ipv4hdr *ip;
	struct grehdr *gre;
};

#define FRAME_HEADER_LEN	50
#define ETH_AND_VLAN	18
#define IP_AND_GRE	32

struct payload{
	_Int32 seq;
	u_char *mpld;
	int plen;
	struct payload *next_pld;
	int pnum;//测试用
};

struct listhdr{
	struct etherhdr eth;
	_Int32 ip_src;
	_Int32 ip_dst;
	struct grehdr gre;
	struct listhdr *next_list;
	struct payload *pld_list;
};

struct listhash{
	struct listhdr *list[PDU_HASH_ACC];
};

//---------------------------
#define ACCESSNW	0xbb02
#define REG_REQUEST	0x01
#define REG_REPLY	0x03
#define REG_UPDATE	0x14
#define REG_ACK	0x15
#define ACCEPTED	0x00
#define A11_ACTIVE_START	0x02
#define A11_ACTIVE_STOP	0x03
#define IPCP_CON_REQUEST	0x01
#define IPCP_CON_ACK	0x02
#define IPCP_CON_NAK	0x03
#define IPCP_CON_REJECT	0x04
#define RADIUS_ACCT_REQ	0x04
#define ACCT_STATUS_START	0x01
#define ACCT_STATUS_STOP	0x02
#define ACCT_STATUS_UPDATE	0x03
#define BCD(x)	(x)&0x0f|0x30

struct udphdr{
	_Int16 src_port;
	_Int16 dst_port;
	_Int16 length;
	_Int16 checksum;
};

#define SGNLHDR_LEN	46

struct signalhdr{
	struct etherhdr *eth;
	struct virlanhdr *vlan;
	struct ipv4hdr *ip;
	struct udphdr *udp;
};

struct TK_MSID{
	_Int32 sip;
	_Int32 dip;
	_Int32 key;
	u_char msid[16];
	u_char meid[15];
	struct TK_MSID *next;
	int p;
};

struct msidhash{
	struct TK_MSID *idlist[MSID_HASH_ACC];
};

struct RADIUS_MSG{
	_Int32 mip;
	_Int32 key;
	u_char msisdn[14];
	struct RADIUS_MSG *next;
};

struct radiushash{
	struct RADIUS_MSG *rdslist[RADIUS_HASH_ACC];
};

struct get_msg{
	struct frame_buf *fbuf;
	struct msidhash *mhash;
	struct radiushash *rhash;
};

struct get_msg * get_msg_make(struct frame_buf *);
void get_msg_free(struct get_msg **);
void *pdu_get(void *);
void *frame_analy(void *);

#endif
