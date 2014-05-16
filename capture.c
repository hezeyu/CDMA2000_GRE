#include <stdio.h>
#include <stdlib.h>
#include "capture.h"

struct cap_msg * cap_msg_make(pcap_t *adhandle){
	struct cap_msg * p = (struct cap_msg *)malloc(sizeof(struct cap_msg));
	p->fbuf = frame_buf_init();
	p->adhandle = adhandle;
	return p;
}

void cap_msg_free(struct cap_msg **c){
	free((*c)->fbuf);
	free(*c);
}

pcap_t * open_eth(){
	pcap_if_t *alldevs, *d;
	pcap_t *adhandle;
	int i=0, inum;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(&alldevs,errbuf)==-1){
		fprintf(stderr,"Error in pcap_findalldevs:%s\n",errbuf);
		return NULL;
	}

	for(d=alldevs;;d=d->next){
		printf("%d, %s",++i,d->name);
		if(d->description)
			printf("(%s)\n",d->description);
		else
			printf("(No description)\n");
	}

	if(i==0){
		printf("\nNo interface found!\n");
		return NULL;
	}

	printf("Enter the interface number (1-%d):", i);
	do{
		scanf("%d", &inum);
	}while(inum < 1 || inum > i);

	for(d=alldevs,i=0;i<inum-1;d=d->next,i++);

	if((adhandle = pcap_open_live(d->name,65536,0,5000,errbuf))==NULL){
		fprintf(stderr,"\nUnable to open the adpater,%s id not supported\n",d->name);
		pcap_freealldevs(alldevs);
		return NULL;
	}

	pcap_freealldevs(alldevs);
	return adhandle;
}

void *frame_capture(void *msg){
	struct frame_buf *fbuf = ((struct cap_msg *)msg)->fbuf;
	pcap_t *adhandle = ((struct cap_msg *)msg)->adhandle;
	struct pcap_pkthdr *header;
	do{
		pthread_mutex_lock(&(fbuf->mutex));
		if(fbuf->front == (fbuf->rear+1)%FRAME_BUF_SIZE)
			pthread_cond_wait(&(fbuf->empty), &(fbuf->mutex));

		if(pcap_next_ex(adhandle,&header,&(fbuf->mframe[fbuf->rear]))>0){
			fbuf->frame_len[fbuf->rear] = header->len;
			fbuf->rear = (fbuf->rear+1)%FRAME_BUF_SIZE;
		}

		pthread_cond_signal(&(fbuf->full));
		pthread_mutex_unlock(&(fbuf->mutex));
	}while(1);
}
