#ifndef _CAPTURE_H_
#define _CAPTURE_H_

#include "structure.h"
#include <pcap/pcap.h>

#define SNAPLEN	1600

pcap_t * open_eth();
void frame_capture(struct frame_buf *, pcap_t *);

#endif

