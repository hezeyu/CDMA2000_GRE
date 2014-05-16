#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/stat.h>
#include "panaly.h"
#include "file.h"
#include "capture.h"

void online_exit(struct cap_msg **c, struct get_msg **g, pcap_t **adhandle){
	cap_msg_free(c);
	get_msg_free(g);
	free(*adhandle);
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

int online_analy(){
	struct cap_msg *cmsg;
	struct get_msg *gmsg;
	pthread_t cap, get;
	int err = 0;
	pcap_t *adhandle = open_eth();

	if(!adhandle)
		return 3;
	cmsg = cap_msg_make(adhandle);
	gmsg = get_msg_make(cmsg->fbuf);

	err = pthread_create(&cap, NULL, frame_capture, (void *)cmsg);
	if(err != 0){
		fprintf(stderr, "can't start frame_capture:%s\n", strerror(err));
		online_exit(&cmsg, &gmsg, &adhandle);
		return 2;
	}
	
	err = pthread_create(&get, NULL, frame_analy, (void *)gmsg);
	if(err != 0){
		fprintf(stderr, "can't start frame_analy:%s\n", strerror(err));
		online_exit(&cmsg, &gmsg, &adhandle);
		return 2;
	}

	if((err = pthread_wait(&cap, &get)) != 0){
		fprintf(stderr, "pthread_wait failed\n");
		online_exit(&cmsg, &gmsg, &adhandle);
		return 2;
	}

	online_exit(&cmsg, &gmsg, &adhandle);

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
		return 1;
	}
	//获得文件总长度
	struct stat mstat;
	if(stat(path,&mstat)<0){
		fprintf(stderr,"%s\n","stat error!");
		fclose(mfile);
		return 1;
	}
	file_len = mstat.st_size;
	printf("%lld\n", file_len);

	pmsg = put_msg_make(mfile, file_len);
	gmsg = get_msg_make(pmsg->fbuf);
	err = pthread_create(&put, NULL, frame_buf_put, (void *)pmsg);
	if(err != 0){
		fprintf(stderr, "can't start frame_buf_put:%s\n", strerror(err));
		offline_exit(&pmsg, &gmsg, mfile);
		return 2;
	}
	
	err = pthread_create(&get, NULL, frame_analy, (void *)gmsg);
	if(err != 0){
		fprintf(stderr, "can't start signal_analy:%s\n", strerror(err));
		offline_exit(&pmsg, &gmsg, mfile);
		return 2;
	}

	if((err = pthread_wait(&put, &get)) != 0){
		fprintf(stderr, "pthread_wait failed\n");
		offline_exit(&pmsg, &gmsg, mfile);
		return 2;
	}

	offline_exit(&pmsg, &gmsg, mfile);

	return 0;
}

int main(int argc, char *argv[]){
	struct timeval tv1, tv2;
	gettimeofday(&tv1, NULL);

	if(argc < 2){
		if(online_analy() > 0)
			fprintf(stderr,"ERROR EXIT!\n");
	}else{
		if(offline_analy(argv[1]) > 0)
			fprintf(stderr,"ERROR EXIT!\n");
	}

	gettimeofday(&tv2, NULL);
	long timeuse=1000000*(tv2.tv_sec-tv1.tv_sec)+(tv2.tv_usec-tv1.tv_usec);
	printf("total time : %ld.%lds\n",timeuse/1000000,timeuse&999999);
	exit(0);
}

