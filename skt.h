#ifndef _SKT_H_
#define _SKT_H_

#include "structure.h"

struct skt_msg{
	struct frame_buf *fbuf;
};

struct skt_msg * skt_msg_make();
void skt_msg_free(struct skt_msg **);
void *frame_socket(void *);

#endif

