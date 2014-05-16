#ifndef _CAPTURE_H_
#define _CAPTURE_H_

#include "structure.h"
#include "pcap.h"

struct cap_msg{
	struct frame_buf *fbuf;
	pcap_t *adhandle;
};

struct cap_msg *cap_msg_make(pcap_t *);
pcap_t *open_eth();
void * frame_capture(void *);

#endif

