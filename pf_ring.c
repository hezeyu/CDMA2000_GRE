#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "pf_ring.h"

#define FRAME_LEN	1600

struct pfr_msg * pfr_msg_make(){
	struct pfr_msg * p = (struct pfr_msg *)malloc(sizeof(struct pfr_msg));
	p->fbuf = frame_buf_init();
	return p;
}

void pfr_msg_free(struct pfr_msg **s){
	free((*s)->fbuf);
	free(*s);
}

void *frame_pfring(void *msg){
	struct frame_buf *fbuf = ((struct pfr_msg *)msg)->fbuf;
	int p=0;
	do{
		if(fbuf->front != (fbuf->rear+1)%FRAME_BUF_SIZE){
			fbuf->mframe[fbuf->rear]=(u_char *)malloc(FRAME_LEN);
			fbuf->rear = (fbuf->rear+1)%FRAME_BUF_SIZE;
			printf("\rframe:%d", ++p);
			fflush(stdout);
		}
	}while(1);

	pthread_exit((void *)3);
}

