#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "skt.h"

#define FRAME_LEN	1600

struct skt_msg * skt_msg_make(){
	struct skt_msg * p = (struct skt_msg *)malloc(sizeof(struct skt_msg));
	p->fbuf = frame_buf_init();
	return p;
}

void skt_msg_free(struct skt_msg **s){
	free((*s)->fbuf);
	free(*s);
}

int get_ifaceIndex(int fd, const char *interfaceName){
	struct ifreq ifr;
	memset(&ifr,0,sizeof(ifr));
	strcpy(ifr.ifr_name,interfaceName);
	if(ioctl(fd,SIOCGIFINDEX,&ifr)==-1){
		printf("ioctl error\n");
		return -1;
	}
	return ifr.ifr_ifindex;
}

int set_iface_promisc(int fd, int dev_id){
	struct packet_mreq mr;
	memset(&mr,0,sizeof(mr));
	mr.mr_ifindex = dev_id;
	mr.mr_type = PACKET_MR_PROMISC;
	if(setsockopt(fd,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&mr,sizeof(mr))==-1){
		printf("set promisc error\n");
		return -1;
	}
	return 0;
}

void *frame_socket(void *msg){
	struct frame_buf *fbuf = ((struct skt_msg *)msg)->fbuf;
	int sockfd, p=0;
	struct sockaddr_ll sll;
	sockfd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = get_ifaceIndex(sockfd,"eth0");
	sll.sll_protocol = htons(ETH_P_ALL);
	if(bind(sockfd,(struct sockaddr *)(&sll),sizeof(sll))==-1){
		printf("bind error\n");
		goto FAIL;
	}
	if(set_iface_promisc(sockfd,sll.sll_ifindex)==-1){
		printf("set promisc error\n");
		goto FAIL;
	}

	do{
		pthread_mutex_lock(&(fbuf->mutex));
		if(fbuf->front == (fbuf->rear+1)%FRAME_BUF_SIZE)
			pthread_cond_wait(&(fbuf->empty), &(fbuf->mutex));

		fbuf->mframe[fbuf->rear]=(u_char *)malloc(FRAME_LEN);
		recv(sockfd,fbuf->mframe[fbuf->rear],FRAME_LEN,MSG_TRUNC);
		fbuf->rear = (fbuf->rear+1)%FRAME_BUF_SIZE;
		printf("\rframe:%d", ++p);
		fflush(stdout);

		pthread_cond_signal(&(fbuf->full));
		pthread_mutex_unlock(&(fbuf->mutex));
	}while(1);
	pthread_exit((void *)3);

FAIL:
	close(sockfd);
	pthread_exit((void *)-1);
}

