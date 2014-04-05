#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include "panaly.h"
#include "file.h"

void err_exit(struct put_msg **p, struct get_msg **g, FILE *f){
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

int main(int argc, char *argv[]){
	if(argc < 3){
		fprintf(stderr,"%s\n","No file path!");
		exit(1);
	}
	struct timeval tv1, tv2;
	FILE *mfile;
	struct put_msg *pmsg;
	struct get_msg *gmsg;
	pthread_t put, get;
	int err = 0, file_len;

	gettimeofday(&tv1, NULL);

//--进行信令分析----------------------------
	mfile = fopen(argv[1], "rb");
	if(mfile == 0){
		fprintf(stderr,"%s\n","No such file!");
		exit(1);
	}
	//获得文件总长度
	fseek(mfile,0,SEEK_END);
	file_len = ftell(mfile);
	fseek(mfile,0,SEEK_SET);

	pmsg = put_msg_make(mfile, file_len);
	gmsg = get_msg_make(pmsg->fbuf);
	err = pthread_create(&put, NULL, &frame_buf_put, (void *)pmsg);
	if(err != 0){
		fprintf(stderr, "can't start frame_buf_put:%s\n", strerror(err));
		err_exit(&pmsg, &gmsg, mfile);
		exit(3);
	}
	
	err = pthread_create(&get, NULL, &signal_analy, (void *)gmsg);
	if(err != 0){
		fprintf(stderr, "can't start signal_analy:%s\n", strerror(err));
		err_exit(&pmsg, &gmsg, mfile);
		exit(3);
	}

	if((err = pthread_wait(&put, &get)) != 0){
		fprintf(stderr, "pthread_wait failed\n");
		err_exit(&pmsg, &gmsg, mfile);
		exit(3);
	}

	put_msg_free(&pmsg);
	fclose(mfile);

//--进行用户数据分析-------------------------
	mfile = fopen(argv[2], "rb");
	if(mfile == 0){
		fprintf(stderr,"%s\n","No such file!");
		exit(1);
	}
	//获得文件总长度
	fseek(mfile,0,SEEK_END);
	file_len = ftell(mfile);
	fseek(mfile,0,SEEK_SET);

	pmsg = put_msg_make(mfile, file_len);
	gmsg->fbuf = pmsg->fbuf;
	err = pthread_create(&put, NULL, &frame_buf_put, (void *)pmsg);
	if(err != 0){
		fprintf(stderr, "can't start frame_buf_put:%s\n", strerror(err));
		err_exit(&pmsg, &gmsg, mfile);
		exit(3);
	}

	err = pthread_create(&get, NULL, &pdu_get, (void *)gmsg);
	if(err != 0){
		fprintf(stderr, "can't start pdu_get:%s\n", strerror(err));
		err_exit(&pmsg, &gmsg, mfile);
		exit(3);
	}
	
	if((err = pthread_wait(&put, &get)) != 0)
		fprintf(stderr, "pthread_wait failed\n");

	put_msg_free(&pmsg);
	get_msg_free(&gmsg);
	fclose(mfile);

	gettimeofday(&tv2, NULL);
	long timeuse=1000000*(tv2.tv_sec-tv1.tv_sec)+(tv2.tv_usec-tv1.tv_usec);
	printf("total time : %ld.%lds\n",timeuse/1000000,timeuse&999999);
	exit(0);
}

