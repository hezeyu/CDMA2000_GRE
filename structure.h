#ifndef _STRUCTURE_H_
#define _STRUCTURE_H_

#define QUIT	1

typedef unsigned char	u_char;
typedef unsigned short	_Int16;
typedef unsigned long	_Int32;

#define FRAME_BUF_SIZE	1280

struct frame_buf{
	u_char *mframe[FRAME_BUF_SIZE];
	int front;
	int rear;
	int quit;
};

struct frame_buf *frame_buf_init();

#endif
