#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "panaly.h"
#include "file.h"
#include "capture.h"
#include "pf_ring.h"

void online_exit_libpcap(struct frame_buf **f, struct get_msg **g){
	int i;
	for(i=0; i<FRAME_BUF_SIZE; i++)
		free((*f)->mframe[i]);
	free((*f));
	get_msg_free(g);
}

void online_exit_pfring(struct pfr_msg **p, struct get_msg **g){
	pfr_msg_free(p);
	get_msg_free(g);
}

void offline_exit(struct put_msg **p, struct get_msg **g, FILE *f){
	put_msg_free(p);
	get_msg_free(g);
	fclose(f);
}

int pthread_wait(pthread_t *thread1, pthread_t *thread2){
	int err = 0;
	err = pthread_join(*thread1, NULL);
	if(err != 0)
		return err;
	err = pthread_join(*thread2, NULL);
	return err;
}

int online_analy_libpcap(){
	struct frame_buf *fbuf = frame_buf_init();
	struct get_msg *gmsg;
	pthread_t get;
	pcap_t *adhandle = open_eth();
	int err;

	if(!adhandle)
		return -3;
	gmsg = get_msg_make(fbuf);

	err = pthread_create(&get, NULL, frame_analy, (void *)gmsg);
	if(err != 0){
		fprintf(stderr,"can't start frame_analy:%s\n",strerror(err));
		online_exit_libpcap(&fbuf, &gmsg);
		return -2;
	}

	frame_capture(fbuf, adhandle);
	online_exit_libpcap(&fbuf, &gmsg);
	return 0;
}

int online_analy_pfring(){
	struct pfr_msg *pmsg;
	struct get_msg *gmsg;
	pthread_t cap, get;
	int err = 0;

	pmsg = pfr_msg_make();
	gmsg = get_msg_make(pmsg->fbuf);

	err = pthread_create(&cap, NULL, frame_pfring, (void *)pmsg);
	if(err != 0){
		fprintf(stderr, "can't start frame_socket:%s\n", strerror(err));
		online_exit_pfring(&pmsg, &gmsg);
		return -2;
	}
	
	err = pthread_create(&get, NULL, frame_analy, (void *)gmsg);
	if(err != 0){
		fprintf(stderr, "can't start frame_analy:%s\n", strerror(err));
		online_exit_pfring(&pmsg, &gmsg);
		return -2;
	}

	if((err = pthread_wait(&cap, &get)) != 0){
		fprintf(stderr, "pthread_wait failed\n");
		online_exit_pfring(&pmsg, &gmsg);
		return -2;
	}

	online_exit_pfring(&pmsg, &gmsg);
	return 0;
}

int offline_analy(char *path){
	FILE *mfile;
	struct put_msg *pmsg;
	struct get_msg *gmsg;
	pthread_t put, get;
	int err = 0;
	long long file_len;
	
	mfile = fopen(path, "rb");
	if(mfile == 0){
		fprintf(stderr,"%s\n","No such file!");
		return -1;
	}
	//获得文件总长度
	struct stat mstat;
	if(stat(path,&mstat)<0){
		fprintf(stderr,"%s\n","stat error!");
		fclose(mfile);
		return -1;
	}
	file_len = mstat.st_size;
	printf("%lld\n", file_len);

	pmsg = put_msg_make(mfile, file_len);
	gmsg = get_msg_make(pmsg->fbuf);
	err = pthread_create(&put, NULL, frame_buf_put, (void *)pmsg);
	if(err != 0){
		fprintf(stderr, "can't start frame_buf_put:%s\n", strerror(err));
		offline_exit(&pmsg, &gmsg, mfile);
		return -2;
	}
	
	err = pthread_create(&get, NULL, frame_analy, (void *)gmsg);
	if(err != 0){
		fprintf(stderr, "can't start signal_analy:%s\n", strerror(err));
		offline_exit(&pmsg, &gmsg, mfile);
		return -2;
	}

	if((err = pthread_wait(&put, &get)) != 0){
		fprintf(stderr, "pthread_wait failed\n");
		offline_exit(&pmsg, &gmsg, mfile);
		return -2;
	}

	offline_exit(&pmsg, &gmsg, mfile);

	return 0;
}

int main(int argc, char *argv[]){
	struct timeval tv1, tv2;
	gettimeofday(&tv1, NULL);

	if(argc < 2){
		online_analy_libpcap();
	}else{
		offline_analy(argv[1]);
	}

	gettimeofday(&tv2, NULL);
	long timeuse=1000000*(tv2.tv_sec-tv1.tv_sec)+(tv2.tv_usec-tv1.tv_usec);
	printf("total time : %ld.%lds\n",timeuse/1000000,timeuse&999999);
	exit(0);
}

