#ifndef _PF_RING_H_
#define _PF_RING_H_

#include "structure.h"

struct pfr_msg{
	struct frame_buf *fbuf;
};

struct pfr_msg * pfr_msg_make();
void pfr_msg_free(struct pfr_msg **);
void *frame_pfring(void *);

#endif

