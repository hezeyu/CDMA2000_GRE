#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "capture.h"

pcap_t * open_eth(){
	pcap_if_t *alldevs, *d;
	pcap_t *adhandle;
	int i=0, inum;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(pcap_findalldevs(&alldevs,errbuf)==-1){
		fprintf(stderr,"Error in pcap_findalldevs:%s\n",errbuf);
		return NULL;
	}

	for(d=alldevs;d;d=d->next){
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

	if((adhandle = pcap_open_live(d->name,SNAPLEN,1,500,errbuf))==NULL){
		fprintf(stderr,"\nUnable to open the adpater,%s id not supported\n",d->name);
		pcap_freealldevs(alldevs);
		return NULL;
	}

	pcap_freealldevs(alldevs);
	return adhandle;
}

int pcount;
struct frame_buf *fbuf;

void dummy_packet(u_char *deviceId, const struct pcap_pkthdr *h,
		const u_char *p){
	if(fbuf->front!=(fbuf->rear+1)%FRAME_BUF_SIZE
			&& p[12]==0x81){
//	 	printf("\r%d", ++pcount);
  	//	fflush(stdout);
//		printf("%d\n", h->len);
		fbuf->mframe[fbuf->rear] = (u_char *)malloc(h->len);
		memcpy(fbuf->mframe[fbuf->rear],p,h->len);
		fbuf->rear = (fbuf->rear+1)%FRAME_BUF_SIZE;
	}
}

void frame_capture(struct frame_buf *f, pcap_t *adhandle){
	fbuf = f;
	pcount = 0;
	printf("capture start...\n");
	fflush(stdout);
	pcap_set_watermark(adhandle, 128);
	pcap_loop(adhandle, -1, dummy_packet, NULL);
	pcap_close(adhandle);
}

