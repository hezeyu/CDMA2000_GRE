#include <stdlib.h>
#include <stdio.h>
#include "panaly.h"
#include "sql.c"

int ppp_complt(u_char *, int, struct framehdr *, 
		struct msidhash *, FILE *);
struct listhdr * ppp_incomplt(u_char *, struct framehdr *, 
		struct listhdr **, FILE *, int);
int flag_find(u_char *, int, int);
void payload_push(struct listhdr *, struct payload *);
void payload_pop(struct listhdr *);
struct listhdr * listhdr_make(struct listhdr **, struct framehdr *);
void listhdr_destroy(struct listhdr **, struct listhdr *);
int packet_restructure(u_char **, struct listhdr *, FILE *);
int payload_splice(u_char **,struct listhdr *,struct payload *,FILE *);
void hash_init(struct listhash *);
int hash_free(struct listhash *, FILE *, FILE *);
void framehdr_make(struct framehdr *, u_char *);
_Int16 short_displace(_Int16);
_Int32 long_displace(_Int32);
int frame_escape(u_char *, int);
void IPCP_handler(u_char *frame, struct framehdr *, struct msidhash *);

struct signalhdr * signalhdr_make(u_char *);
struct TK_MSID * tkmsid_make(u_char *, struct signalhdr *, int);
void msidhash_join(struct msidhash *, struct TK_MSID *);

int ppp_complt(u_char *frame, int frame_size, struct framehdr *fh, 
		struct  msidhash *mh, FILE *output){
	//返回获得的IP数据包个数
	int ipnum = 0, start = 0, end = 0;
	_Int16 *protocol = 0, *size = 0;
	u_char t[2];
	while(start < frame_size){
		if((end = flag_find(frame, frame_size, start+1)) == -1)
			break;
		start+=1;
		if(start != end){
			frame_escape((frame+start),end-start);
			protocol = (_Int16 *)(frame+start+2);
			switch(*protocol){
				case IPV4:
					//是IP协议说明是数据帧，进行解封装处理
					start+=4;
					t[0] = frame[start+2]; t[1] = frame[start+3];
					size = (_Int16 *)t;
					*size = short_displace(*size);
					fwrite(size, 1, sizeof(_Int16), output);
					fwrite((frame+start), 1, *size, output);
					ipnum++;
					break;
				case IPCP:
					start+=4;
					IPCP_handler((frame+start), fh, mh);
					break;
				default:
					break;
			}
			start = end;
		}
	}
	return ipnum;
}

struct listhdr * ppp_incomplt(u_char *frame, struct framehdr *fh, 
		struct listhdr **lh, FILE *output, int pnum){
	struct listhdr *l = *lh;
	//查找是否有此key的缓存队列
	while(l!=NULL){
		if(l->gre.key == fh->gre->key)
			break;
		l = l->next_list;
	}

	if(l==NULL)//没有记录该key的队列，创建新队列
		l = listhdr_make(lh, fh);

	//生成payload单元并加入相应的队列尾部
	struct payload *p;
	p=(struct payload *)malloc(sizeof(struct payload));
	p->seq = fh->gre->seq;
	p->plen = fh->ip->total_len - IP_AND_GRE;
	p->mpld = (u_char *)malloc(p->plen*sizeof(u_char));
	p->next_pld = NULL;
	p->pnum = pnum;//测试用
	int i=0;
	for(; i<p->plen; i++)
		p->mpld[i] = frame[i+FRAME_HEADER_LEN];

	payload_push(l, p);
	return l;
}

void IPCP_handler(u_char *frame, struct framehdr *fh, struct msidhash *mh){
	if(frame[0]==IPCP_CON_NAK){
		//		printf("find a NAK\n");
		_Int32 j = fh->ip->src+fh->ip->dst+fh->gre->key;
		int hash_pos = HASH(j, MSID_HASH_ACC);
		struct TK_MSID *t = mh->idlist[hash_pos];
		while(t!=NULL){
			if(fh->gre->key==t->key){
				u_char c[4]={frame[6],frame[7],frame[8],frame[9]};
				_Int32 *i = (_Int32 *)c;
				sql_insert(t->msid,long_displace(*i),
						t->key,t->sip,t->dip);
				break;
			}
			t = t->next;
		}
	}
}

int flag_find(u_char *str, int len, int start){
	int i;
	for(i=start;i<len;i++)
		if(str[i] == PPP_FLAG)
			return i;
	return -1;
}

int packet_restructure(u_char **tar, struct listhdr *l, FILE *log){
	int pdu_len = -1;
	struct payload *p = l->pld_list;
	if(p->next_pld == NULL)
		return pdu_len;

	while(p->next_pld->next_pld != NULL)
		p = p->next_pld;

	struct payload *last = p->next_pld;	//队列中最后一个单元
	if((p->seq+1) == last->seq){
		//获取的帧seq连续,末尾不是标志位直接返回，是则进行组包分析
		if(last->mpld[last->plen-1] == PPP_FLAG)
			pdu_len = payload_splice(tar, l, NULL, log);
	}else	//seq不连续对队列中除最后单元的部分进行组包
		pdu_len = payload_splice(tar, l, last, log);

	return pdu_len;
}

void payload_push(struct listhdr *l, struct payload *p){
	struct payload *t = l->pld_list;
	if(t == NULL){
		p->next_pld = l->pld_list;
		l->pld_list = p;
	}else{
		while(t->next_pld != NULL)
			t = t->next_pld;
		p->next_pld = t->next_pld;
		t->next_pld = p;
	}
}

void payload_pop(struct listhdr *l){
	struct payload *t;
	t = l->pld_list->next_pld;
	free(l->pld_list);
	l->pld_list = t;
}

struct listhdr * listhdr_make(struct listhdr **list, struct framehdr *fh){
	struct listhdr *l;
	l = (struct listhdr *)malloc(sizeof(struct listhdr));
	l->eth = *(fh->eth);
	int i;
	l->ip_src = fh->ip->src;
	l->ip_dst = fh->ip->dst;
	l->gre = *(fh->gre);
	l->pld_list = NULL;
	l->next_list = *list;
	*list = l;
	return l;
}

void listhdr_destroy(struct listhdr **list, struct listhdr *l){
	struct listhdr *t = *list, *v;
	if(*list == l){
		v = l->next_list;
		free(l);
		*list = v;
		return;
	}

	while(t->next_list != l)
		t = t->next_list;
	v = l->next_list;
	free(l);
	t->next_list = v;
}

int payload_splice(u_char **str, struct listhdr *l, struct payload *p, FILE *log){
	int size = 0, i = 0, start = 0;
	*str = NULL;
	while(l->pld_list != p){//先找到帧的起始标志
		start=flag_find(l->pld_list->mpld, l->pld_list->plen, 0);
		if(start!=-1 && start!=l->pld_list->plen-1){
			if(l->pld_list->mpld[start+1]==PPP_FLAG)
				start++;
			size = size + l->pld_list->plen - start;
			*str = (u_char *)realloc(*str, size*sizeof(u_char));
			for(;i<size;i++)
				(*str)[i] = l->pld_list->mpld[start+i];
			fprintf(log, "%d\t", l->pld_list->pnum);
			payload_pop(l);
			break;
		}
		fprintf(log, "%d\t", l->pld_list->pnum);
		payload_pop(l);
	}
	while(l->pld_list != p){
		size = size + l->pld_list->plen;
		*str = (u_char *)realloc(*str, size*sizeof(u_char));
		for(;i<size;i++)
			(*str)[i] = l->pld_list->mpld[l->pld_list->plen+i-size];

		//释放队列中相应单元
		fprintf(log, "%d\t", l->pld_list->pnum);
		payload_pop(l);
	}
	return size;
}

void hash_init(struct listhash *hash){
	int i;
	for(i=0; i<PDU_HASH_ACC; i++){
		hash->list[i] = NULL;
	}
}

int hash_free(struct listhash *hash, FILE *output, FILE *log){
	int i, n=0, m=0, k=0;
	u_char *str = NULL;
	for(i=0; i<PDU_HASH_ACC; i++){
		struct listhdr *l = hash->list[i];
		while(l != NULL){
			n = 0;
			fprintf(log, "in hash %d:",i);
			if((k=payload_splice(&str, l, NULL, log)) > 0)
				n = ppp_complt(str, k, NULL, NULL, output);
			m+=n;
			fprintf(log, "packets:%d\n",n);
			free(str);
			str = NULL;
			listhdr_destroy(&hash->list[i], l);
			l = hash->list[i];
		}
	}
	return m;
}

void framehdr_make(struct framehdr *fh, u_char *frame){
	int p = 0;
	fh->eth = (struct etherhdr *)frame;
	p+=sizeof(struct etherhdr);
	fh->vlan = (struct virlanhdr *)(frame + p);
	p+=sizeof(struct virlanhdr);
	fh->ip = (struct ipv4hdr *)(frame + p);
	fh->ip->total_len = short_displace(fh->ip->total_len);
	fh->ip->src = long_displace(fh->ip->src);
	fh->ip->dst = long_displace(fh->ip->dst);
	p+=sizeof(struct ipv4hdr);
	fh->gre = (struct grehdr *)(frame + p);
	fh->gre->seq = long_displace(fh->gre->seq);
	fh->gre->key = long_displace(fh->gre->key);
}

_Int16 short_displace(_Int16 i){
	int t[2];
	t[0] = i>>8 & 0x00ff;
	t[1] = i<<8 & 0xff00;
	return (t[0] | t[1]);
}

_Int32 long_displace(_Int32 i){
	int t[4];
	t[0] = i<<24 & 0xff000000;
	t[1] = i<<8 & 0x00ff0000;
	t[2] = i>>8 & 0x0000ff00;
	t[3] = i>>24 & 0x000000ff;
	return (t[0]|t[1]|t[2]|t[3]);
}

int frame_escape(u_char *frame, int frame_size){
	int i, j, size = frame_size;
	u_char t;
	for(i=0,j=0;j<frame_size;i++,j++){
		if(frame[j] == ESCAPE_OCTET){
			t = 0x20 ^ frame[j+1];
			if(t<0x20 || frame[j+1]==0x5e || frame[j+1]==0x5d){
				frame[i] = t;
				size-=1;
				j+=1;
			}
			else{
				frame[i] = frame[j];
				frame[++i] = frame[++j];
			}
		}else{
			frame[i] = frame[j];
		}
	}
	return size;
}

void *pdu_get(void *msg){
	printf("PDU analyzing...\n");
	struct frame_buf *fbuf = ((struct get_msg *)msg)->fbuf;
	struct msidhash *mhash = ((struct get_msg *)msg)->mhash;
	sql_init();
	struct listhdr *l=NULL;
	u_char *frame=NULL, *tar=NULL;
	FILE *output = fopen("./packet", "wb");
	FILE *log = fopen("./log", "wb");
	struct listhash packet_hash;
	hash_init(&packet_hash);
	struct framehdr fh;
	//p分析过的帧数，ip_acc获得的ip数据包数,pld_len组包后获得的pdu长度
	int p=0, ip_acc=0, hash_pos=0, pld_len=0;
	int t=0;//t临时变量
	do{
		pthread_mutex_lock(&(fbuf->mutex));
		if(fbuf->front == fbuf->rear){
			if(fbuf->quit == QUIT)
				break;
			pthread_cond_wait(&(fbuf->full), &(fbuf->mutex));
		}
		p++;
		frame = fbuf->mframe[fbuf->front];
		fbuf->front = (fbuf->front+1)%FRAME_BUF_SIZE;
		pthread_cond_signal(&(fbuf->empty));
		pthread_mutex_unlock(&(fbuf->mutex));
		framehdr_make(&fh, frame);
		t = fh.ip->total_len + ETH_AND_VLAN;//目的是去掉帧结尾的补位

		if(frame[FRAME_HEADER_LEN] == PPP_FLAG&&frame[t-1] == PPP_FLAG)
			//封装完整
			ip_acc+=ppp_complt((frame+FRAME_HEADER_LEN),
					t-FRAME_HEADER_LEN,&fh,mhash,output);
		else{
			//封装不完整
			hash_pos = HASH(fh.gre->key, PDU_HASH_ACC);
			l = ppp_incomplt(frame,&fh,&packet_hash.list[hash_pos],output,p);
			//跳转到组包程序
			pld_len = packet_restructure(&tar, l, log);
			if(pld_len > 0){
				t = ppp_complt(tar, pld_len, &fh, mhash, output);
				ip_acc+=t;
				fprintf(log, "packets:%d\n", t);
			}else if(pld_len == 0)
				fprintf(log, "packets:%d\n", 0);
			if(l->pld_list == NULL)
				listhdr_destroy(&packet_hash.list[hash_pos], l);
			free(tar);
			tar = NULL;
		}
		//处理完一个帧后释放空间
		free(frame);
		frame = NULL;
	}while(1);
	//文件中所有帧扫描结束，对表中剩余数据进行处理并释放空间
	ip_acc+=hash_free(&packet_hash, output, log);
	fclose(output);
	fclose(log);
	printf("PDU analysis finished\nget %d ip packets\n", ip_acc);
	pthread_exit((void *)2);
}

struct signalhdr * signalhdr_make(u_char *frame){
	struct signalhdr *s;
	s = (struct signalhdr *)malloc(sizeof(struct signalhdr));
	int p = 0;
	s->eth = (struct etherhdr *)frame;
	p+=sizeof(struct etherhdr);
	s->vlan = (struct virlanhdr *)(frame + p);
	p+=sizeof(struct virlanhdr);
	s->ip = (struct ipv4hdr *)(frame + p);
	s->ip->src = long_displace(s->ip->src);
	s->ip->dst = long_displace(s->ip->dst);
	p+=sizeof(struct ipv4hdr);
	s->udp = (struct udphdr *)(frame + p);
	return s;
}

struct TK_MSID * tkmsid_make(u_char *frame, struct signalhdr *s, int p){
	struct TK_MSID *t;
	t = (struct TK_MSID *)malloc(sizeof(struct TK_MSID));
	int i;
	t->sip = s->ip->src;
	t->dip = s->ip->dst;
	_Int32 *k = (_Int32 *)(frame+4);
	t->key = long_displace(*k);
	for(i=0;i<8;i++)
		t->msid[i] = frame[15+i];
	t->next = NULL;
	t->p = p;
	return t;
}

void msidhash_join(struct msidhash *mhash, struct TK_MSID *t){
	int hash_pos = HASH(t->sip+t->dip+t->key, MSID_HASH_ACC);
	struct TK_MSID *tmp = mhash->idlist[hash_pos];
	while(tmp!=NULL){
		if(t->key==tmp->key)
			return;
		tmp = tmp->next;
	}
	t->next = mhash->idlist[hash_pos];
	mhash->idlist[hash_pos] = t;
}

struct get_msg * get_msg_make(struct frame_buf *fbuf){
	struct get_msg *g;
	g = (struct get_msg *)malloc(sizeof(struct get_msg));
	g->fbuf = fbuf;
	g->mhash = (struct msidhash *)malloc(sizeof(struct msidhash));
	int i;
	for(i=0;i<MSID_HASH_ACC;i++)
		g->mhash->idlist[i] = NULL;
	return g;
}

void get_msg_free(struct get_msg **g){
	int i,j;
	struct TK_MSID *t;
	for(i=0;i<MSID_HASH_ACC;i++){
		//					j=0;
		while((*g)->mhash->idlist[i]!=NULL){
			//						j++;
			//			t = (*g)->mhash->idlist[i];
			//			printf("%.6d:\t",t->p);
			//			for(j=0;j<4;j++)
			//				printf("%d.", t->sip[j]);
			//			printf("\t");
			//			for(j=0;j<4;j++)
			//				printf("%d.", t->dip[j]);
			//			printf("\t%.4x\t", t->key);
			//			for(j=0;j<8;j++)
			//				printf("%.2x", t->msid[j]);
			//			printf("\n");

			t = (*g)->mhash->idlist[i]->next;
			free((*g)->mhash->idlist[i]);
			(*g)->mhash->idlist[i] = t;
		}
		//					printf("%d in hash %d\n", j, i);
	}
	free(*g);
}

void *signal_analy(void *msg){
	printf("signal analyzing...\n");
	struct frame_buf *fbuf = ((struct get_msg *)msg)->fbuf;
	struct msidhash *mhash = ((struct get_msg *)msg)->mhash;
	struct signalhdr *s = NULL;
	struct TK_MSID *t;
	u_char *frame;
	int p = 0;
	do{
		pthread_mutex_lock(&(fbuf->mutex));
		if(fbuf->front == fbuf->rear){
			if(fbuf->quit == QUIT)
				break;
			pthread_cond_wait(&(fbuf->full), &(fbuf->mutex));
		}
		p++;
		//信令处理
		frame = fbuf->mframe[fbuf->front];
		fbuf->mframe[fbuf->front] = NULL;
		fbuf->front = (fbuf->front+1)%FRAME_BUF_SIZE;
		pthread_cond_signal(&(fbuf->empty));
		pthread_mutex_unlock(&(fbuf->mutex));

		s = signalhdr_make(frame);
		if(s->udp->src_port==ACCESSNW && s->udp->dst_port==ACCESSNW){
			switch(frame[SGNLHDR_LEN]){
				case REG_REPLY:
					if(frame[SGNLHDR_LEN+1]==ACCEPTED){
						t = tkmsid_make((frame+SGNLHDR_LEN+20), s, p);
						msidhash_join(mhash, t);
					}
					break;
				default:
					break;
			}
		}
		//一个帧处理完后释放内存，移动队列游标
		free(s);
		free(frame);
		frame = NULL;
	}while(1);
	printf("signal analysis finished\n");
	pthread_exit((void *)2);
}

