#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include "file.h"


struct buffer * file_buf_init(FILE *mfile){
	struct buffer *mbuf = (struct buffer *)malloc(sizeof(struct buffer));
	mbuf->forward = 0;
	mbuf->bnum = 0;
	fread((void *)mbuf->buf[0],1,BLOCK_SIZE,mfile);
	return mbuf;
}

struct frame_buf * frame_buf_init(){
	struct frame_buf *fbuf = (struct frame_buf *)malloc(sizeof(struct frame_buf));
	int i;
	for(i=0; i<FRAME_BUF_SIZE; i++){
		fbuf->mframe[i] = NULL;
	}
	fbuf->front = 0;
	fbuf->rear = 0;
	pthread_mutex_init(&fbuf->mutex, NULL);
	pthread_cond_init(&fbuf->empty, NULL);
	pthread_cond_init(&fbuf->full, NULL);
	fbuf->quit = 0;
	return fbuf;
}

struct put_msg *put_msg_make(FILE *mfile, long long file_len){
	struct put_msg * p = (struct put_msg *)malloc(sizeof(struct put_msg));
	p->mbuf = file_buf_init(mfile);
	p->fbuf = frame_buf_init();
	p->mfile = mfile;
	p->file_len = file_len;
	return p;
}

void put_msg_free(struct put_msg **p){
	free((*p)->mbuf);
	free((*p)->fbuf);
	free(*p);
}

int pkthdr_read(struct buffer *mbuf, struct pkthdr *mpkthdr, FILE *mfile){
	int i = sizeof(struct pkthdr);
	if((BLOCK_SIZE - mbuf->forward)>=i){	//头部完整
		sncpy((u_char *)mpkthdr, (mbuf->buf[mbuf->bnum]+mbuf->forward), i);
		mbuf->forward+=i;
		if(mpkthdr->real_len > 2000 || mpkthdr->real_len < 0)
			printf("\n1\t%lu\n",mpkthdr->real_len);
	}else{	//头部不完整，需要继续读取文件
		int k = BLOCK_SIZE - mbuf->forward;
		sncpy((u_char *)mpkthdr, (mbuf->buf[mbuf->bnum]+mbuf->forward), k);

		mbuf_write(mbuf, mfile);
		sncpy(((u_char *)mpkthdr+k), mbuf->buf[mbuf->bnum], i-k);
		mbuf->forward = (i+mbuf->forward)%(BLOCK_SIZE);
		if(mpkthdr->real_len > 2000 || mpkthdr->real_len < 0)
			printf("\n2\t%lu\n",mpkthdr->real_len);
	}

	return i;
}

void sncpy(u_char *tar, u_char *src, int n){
	int i;
	for(i=0; i<n; i++)
		tar[i] = src[i];
}

void mbuf_write(struct buffer *mbuf, FILE *mfile){
	mbuf->bnum = (mbuf->bnum+1)%BUF_ACC;
	if(!feof(mfile))
		fread((void *)mbuf->buf[mbuf->bnum],1,BLOCK_SIZE,mfile);
}

//获得一个完整的数据帧
u_char * frame_make(int size, struct buffer *mbuf, FILE *mfile){
	u_char * t_frame = (u_char *)malloc(size*sizeof(u_char));
	if((BLOCK_SIZE - mbuf->forward)>=size){
		sncpy(t_frame, (mbuf->buf[mbuf->bnum]+mbuf->forward), size);
		mbuf->forward+=size;
	}else{
		int k = BLOCK_SIZE - mbuf->forward;
		sncpy(t_frame, (mbuf->buf[mbuf->bnum]+mbuf->forward), k);

		mbuf_write(mbuf, mfile);
		sncpy((t_frame+k), mbuf->buf[mbuf->bnum], size-k);
		mbuf->forward = (size+mbuf->forward)%(BLOCK_SIZE);
	}
	return t_frame;
}

void *frame_buf_put(void *msg){
	struct buffer *mbuf = ((struct put_msg *)msg)->mbuf;
	FILE *mfile = ((struct put_msg *)msg)->mfile;
	long long file_len = ((struct put_msg *)msg)->file_len;
	struct frame_buf *fbuf = ((struct put_msg *)msg)->fbuf;

	long long rd_already = 0;	//记录已经处理的字节数
	//获取文件信息

	mbuf->forward+=sizeof(struct filehdr);
	rd_already+=mbuf->forward;

	struct pkthdr mpkthdr;

//	do{
//		pthread_mutex_lock(&(fbuf->mutex));
//
//		if(rd_already >= file_len){
//			fbuf->quit = QUIT;
//			pthread_mutex_unlock(&(fbuf->mutex));
//			pthread_exit((void *)1);
//		}
//
//		if(fbuf->front == (fbuf->rear+1)%FRAME_BUF_SIZE)
//			pthread_cond_wait(&(fbuf->empty), &(fbuf->mutex));
//
//		rd_already += pkthdr_read(mbuf, &mpkthdr, mfile);
//
//		//读取完整数据帧并加入队列
//		fbuf->mframe[fbuf->rear] = 
//			frame_make(mpkthdr.real_len, mbuf, mfile);
//		fbuf->rear = (fbuf->rear+1)%FRAME_BUF_SIZE;
//
//		rd_already+=mpkthdr.real_len;
//
//		pthread_cond_signal(&(fbuf->full));
//		pthread_mutex_unlock(&(fbuf->mutex));
//	}while(1);

	do{
		if(rd_already >= file_len){
			fbuf->quit = QUIT;
			pthread_exit((void *)1);
		}

		if(fbuf->front != (fbuf->rear+1)%FRAME_BUF_SIZE){
			rd_already += pkthdr_read(mbuf, &mpkthdr, mfile);

			//读取完整数据帧并加入队列
			fbuf->mframe[fbuf->rear] = 
				frame_make(mpkthdr.real_len, mbuf, mfile);
			fbuf->rear = (fbuf->rear+1)%FRAME_BUF_SIZE;

			rd_already+=mpkthdr.real_len;
		}
	}while(1);
}

