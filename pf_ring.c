#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "pf_ring.h"

pfring * open_pfring(char *d){
	pfring *pd = NULL;
	char *device = NULL;
	u_int32_t flags = 0;

	device = d;
	if(device == NULL)
		device = DEFAULT_DEVICE;
	flags |= PF_RING_PROMISC;
	flags |= PF_RING_DNA_SYMMETRIC_RSS;

	pd = pfring_open(device, PFRING_SNAPLEN, flags);
	if(pd == NULL){
		fprintf(stderr,"pfring_open error\n");
		return NULL;
	}else{
		u_int32_t version;
		pfring_version(pd, &version);
		printf("using PF_RING v.%d.%d.%d\n",
				(version & 0xFFFF0000)>>16,
				(version & 0x0000FF00)>>8,
				version & 0x000000FF);
	}

	return pd;
}

struct frame_buf *fbuf;
int pfcount;

void pf_dummy_packet(const struct pfring_pkthdr *h, const u_char *p,
		const u_char *user_bytes){
	if(fbuf->front!=(fbuf->rear+1)%FRAME_BUF_SIZE
			&& p[12]==0x81){
//		printf("\r%d", ++pfcount);
//		fflush(stdout);
//		printf("%d\n", h->len);
		fbuf->mframe[fbuf->rear] = (u_char *)malloc(h->len);
		memcpy(fbuf->mframe[fbuf->rear],p,h->len);
		fbuf->rear = (fbuf->rear+1)%FRAME_BUF_SIZE;
	}
}

int frame_pfring(pfring *pd, struct frame_buf *f){
	fbuf = f;
	pfcount = 0;
	packet_direction direction = rx_and_tx_direction;
	int rc;

	pfring_set_direction(pd, direction);

	if((rc = pfring_set_socket_mode(pd, recv_only_mode)) != 0)
		fprintf(stderr, "pfring_set_socket_mode returned [rc=%d]\n", rc);

	pfring_set_application_stats(pd, "statistics not yet computed, please try again...\n");
	
	if(pfring_enable_ring(pd) != 0){
		fprintf(stderr, "unable to enable ring\n");
		pfring_close(pd);
		return -1;
	}

	printf("capture start...\n");
	pfring_loop(pd, pf_dummy_packet, (u_char *)NULL, 1);
	pfring_close(pd);
	return 0;
}

