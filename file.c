#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "file.h"


struct buffer * file_buf_init(FILE *mfile){
	struct buffer *mbuf = (struct buffer *)malloc(sizeof(struct buffer));
	mbuf->forward = 0;
	mbuf->bnum = 0;
	int i;
	for(i=0; i<BUF_ACC; i++){
		mbuf->buf[i] = (u_char *)malloc(BLOCK_SIZE);
		pthread_mutex_init(&mbuf->b_mutex[i], NULL);
		fread((void *)mbuf->buf[i],1,BLOCK_SIZE,mfile);
	}
	return mbuf;
}

struct frame_buf * frame_buf_init(){
	struct frame_buf *fbuf = (struct frame_buf *)malloc(sizeof(struct frame_buf));
	int i;
	for(i=0; i<FRAME_BUF_SIZE; i++){
		fbuf->mframe[i] = NULL;
		fbuf->frame_len[i] = 0;
	}
	fbuf->front = 0;
	fbuf->rear = 0;
	pthread_mutex_init(&fbuf->mutex, NULL);
	pthread_cond_init(&fbuf->empty, NULL);
	pthread_cond_init(&fbuf->full, NULL);
	fbuf->quit = 0;
	return fbuf;
}

struct put_msg *put_msg_make(FILE *mfile, int file_len){
	struct put_msg * p = (struct put_msg *)malloc(sizeof(struct put_msg));
	p->mbuf = file_buf_init(mfile);
	p->fbuf = frame_buf_init();
	p->mfile = mfile;
	p->file_len = file_len;
	return p;
}

void put_msg_free(struct put_msg **p){
	int i;
	for(i=0; i<BUF_ACC; i++)
		free((*p)->mbuf->buf[i]);
	free((*p)->mbuf);
	free((*p)->fbuf);
	free(*p);
}

int pkthdr_read(struct buffer *mbuf, struct pkthdr *mpkthdr, FILE *mfile){
	int i = sizeof(struct pkthdr);
	if((BLOCK_SIZE - mbuf->forward)>=i){	//头部完整
		sncpy((u_char *)mpkthdr, (mbuf->buf[mbuf->bnum]+mbuf->forward), i);
		mbuf->forward+=i;
	}else{	//头部不完整，需要继续读取文件
		int k = BLOCK_SIZE - mbuf->forward;
		sncpy((u_char *)mpkthdr, (mbuf->buf[mbuf->bnum]+mbuf->forward), k);

		pthread_mutex_unlock(&(mbuf->b_mutex[mbuf->bnum]));
		mbuf->bnum = (mbuf->bnum+1)%BUF_ACC;
		pthread_mutex_lock(&(mbuf->b_mutex[mbuf->bnum]));

		sncpy(((u_char *)mpkthdr+k), mbuf->buf[mbuf->bnum], i-k);
		mbuf->forward = (i+mbuf->forward)%(BLOCK_SIZE);
	}
	//输出pkthdr信息

	return i;
}

void sncpy(u_char *tar, u_char *src, int n){
	int i;
	for(i=0; i<n; i++)
		tar[i] = src[i];
}

void *pfread(void *msg){
	struct buffer *mbuf = ((struct pfread_msg *)msg)->mbuf;
	FILE *mfile = ((struct pfread_msg *)msg)->mfile;
	int num = 0;
	do{
		if(num != mbuf->bnum){
			pthread_mutex_lock(&(mbuf->b_mutex[num]));
			fread((void *)mbuf->buf[num],1,BLOCK_SIZE,mfile);
			pthread_mutex_unlock(&(mbuf->b_mutex[num]));
			num = (num+1)%BUF_ACC;
		}
	}while(!feof(mfile));
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
		
		pthread_mutex_unlock(&(mbuf->b_mutex[mbuf->bnum]));
		mbuf->bnum = (mbuf->bnum+1)%BUF_ACC;
		pthread_mutex_lock(&(mbuf->b_mutex[mbuf->bnum]));

		sncpy((t_frame+k), mbuf->buf[mbuf->bnum], size-k);
		mbuf->forward = (size+mbuf->forward)%(BLOCK_SIZE);
	}
	return t_frame;
}

void *frame_buf_put(void *msg){
	struct buffer *mbuf = ((struct put_msg *)msg)->mbuf;
	FILE *mfile = ((struct put_msg *)msg)->mfile;
	int file_len = ((struct put_msg *)msg)->file_len;
	struct frame_buf *fbuf = ((struct put_msg *)msg)->fbuf;

	int rd_already = 0;	//记录已经处理的字节数
	//获取文件信息
	pthread_mutex_lock(&(mbuf->b_mutex[mbuf->bnum]));

	struct filehdr * fheader = (struct filehdr *)(mbuf->buf[mbuf->bnum]+mbuf->forward);
	mbuf->forward+=sizeof(struct filehdr);
	rd_already+=mbuf->forward;

	struct pkthdr mpkthdr;
	int p=0;

	//创建读文件线程
	pthread_t file_rd;
	struct pfread_msg pmsg = {mbuf, mfile};
	pthread_create(&file_rd, NULL, &pfread, (void *)&pmsg);

	do{
		pthread_mutex_lock(&(fbuf->mutex));

		if(rd_already >= file_len){
			fbuf->quit = QUIT;
			pthread_mutex_unlock(&(fbuf->mutex));
			pthread_exit((void *)1);
		}

		if(fbuf->front == (fbuf->rear+1)%FRAME_BUF_SIZE)
			pthread_cond_wait(&(fbuf->empty), &(fbuf->mutex));

		p++;
		rd_already += pkthdr_read(mbuf, &mpkthdr, mfile);

		//读取完整数据帧并加入队列
		fbuf->mframe[fbuf->rear] = 
			frame_make(mpkthdr.real_len, mbuf, mfile);
		fbuf->frame_len[fbuf->rear] = mpkthdr.real_len;
		fbuf->rear = (fbuf->rear+1)%FRAME_BUF_SIZE;

		rd_already+=mpkthdr.real_len;

		pthread_cond_signal(&(fbuf->full));
		pthread_mutex_unlock(&(fbuf->mutex));
	}while(1);
}

