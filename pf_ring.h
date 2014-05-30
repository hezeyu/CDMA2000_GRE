#ifndef _PF_RING_H_
#define _PF_RING_H_

#include "structure.h"
#include "pfring.h"

#define DEFAULT_DEVICE	"eth0"
#define PFRING_SNAPLEN	1600

pfring * open_pfring(char *);
int frame_pfring(pfring *, struct frame_buf *);

#endif

