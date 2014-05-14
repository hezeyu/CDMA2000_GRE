#ifndef _FILE_H_
#define _FILE_H_

#include "structure.h"

#define BLOCK_SIZE	256*1024//每次读入文件的大小
#define BUF_ACC	2	//缓冲区个数
#define BUF_READ	0
#define BUF_WRITE	1

//file header of pcap file
struct filehdr{
	_Int32 magic;
	_Int16 major_ver;
	_Int16 minor_ver;
	_Int32 time_zone;
	_Int32 time_stamp;
	_Int32 snap_len;
	_Int32 link_type;
};

//packet header in pcap file
struct pkthdr{
	_Int32 GMT;
	_Int32 mtime;
	_Int32 real_len;
	_Int32 cap_len;
};

struct buffer{
	u_char buf[BUF_ACC][BLOCK_SIZE];
	pthread_mutex_t b_mutex[BUF_ACC];
	int bnum;
	int forward;
};

struct pfread_msg{
	struct buffer *mbuf;
	FILE *mfile;
};

struct put_msg{
	struct buffer *mbuf;
	struct frame_buf *fbuf;
	FILE *mfile;
	long long file_len;
};

void *frame_buf_put(void *);//frame_buf写
struct put_msg *put_msg_make(FILE *, long long);
void put_msg_free(struct put_msg **);

struct buffer * file_buf_init(FILE *);
struct frame_buf * frame_buf_init();
int pkthdr_read(struct buffer *, struct pkthdr *, FILE *);
void sncpy(u_char *, u_char *, int);
void mbuf_write(struct buffer *, FILE *);
u_char * frame_make(int, struct buffer *, FILE *);

#endif

