#include <stdlib.h>
#include <stdio.h>
#include "mysql/mysql.h"
#include "structure.h"

#define SQL_FAILED	-1
#define SQL_LEN	256
#define MSID_LEN	16
#define SERVER_HOST	"localhost"
#define USER_NAME	"hezeyu"
#define PASSWORD	"1"
#define DB_NAME	"gre"
#define TABLE_NAME	"ms_info"

MYSQL msql;

char *id_translate(u_char *msid){
	char *tar = (char *)malloc(16);
	sprintf(tar, "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x",
			msid[0],msid[1],msid[2],msid[3],
			msid[4],msid[5],msid[6],msid[7]);
	return tar;
}

int sql_init(){
	if(!mysql_init(&msql)){
		fprintf(stderr, "mysql_init failed!\n");
		return SQL_FAILED;
	}

	if(!mysql_real_connect(&msql,SERVER_HOST,USER_NAME,PASSWORD,DB_NAME,0,NULL,0)){
		fprintf(stderr, "mysql_real_connect failed!\n");
		return SQL_FAILED;
	}

	u_char query[SQL_LEN];
	sprintf(query, "DROP TABLE %s", TABLE_NAME);
	mysql_query(&msql, query);
	sprintf(query, "CREATE TABLE %s(msid VARCHAR(8),mip INT UNSIGNED,"
			"grekey INT UNSIGNED, srcip INT UNSIGNED, dstip INT UNSIGNED)", 
			TABLE_NAME);
	if(mysql_query(&msql, query)){
		fprintf(stderr, "create table error %d:%s\n",
				mysql_errno(&msql), mysql_error(&msql));
		return SQL_FAILED;
	}

	return 0;
}

int sql_insert(u_char *msid, _Int32 mip, _Int32 key, _Int32 src, _Int32 dst){
	int r = 0;
	char *id = id_translate(msid);
	u_char insert[SQL_LEN];
	sprintf(insert,
			"INSERT INTO %s(msid,mip,grekey,srcip,dstip) VALUES"
			"('%s',%lu,%lu,%lu,%lu)",
			TABLE_NAME, id, mip, key, src, dst);
	if(mysql_query(&msql, insert)){
		fprintf(stderr, "insert error %d:%s\n",
				mysql_errno(&msql), mysql_error(&msql));
		r = SQL_FAILED;
	}
	free(id);
	id=NULL;
	return r;
}

