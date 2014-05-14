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
#define TABLE_NAME	"ms_info_test"

MYSQL msql;

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
	sprintf(query, "CREATE TABLE %s(MSISDN VARCHAR(13),MSID VARCHAR(15),"
			"MEID VARCHAR(14),IP INT UNSIGNED,GK INT UNSIGNED)", 
			TABLE_NAME);
	if(mysql_query(&msql, query)){
		fprintf(stderr, "create table error %d:%s\n",
				mysql_errno(&msql), mysql_error(&msql));
		return SQL_FAILED;
	}

	return 0;
}

int sql_insert(u_char *msisdn, u_char *msid, u_char *meid, _Int32 mip, _Int32 key){
	int r = 0;
	u_char insert[SQL_LEN];
	sprintf(insert,
			"INSERT INTO %s(MSISDN,MSID,MEID,IP,GK) VALUES"
			"('%s','%s','%s',%lu,%lu)",
			TABLE_NAME, msisdn, msid, meid, mip, key);
	if(mysql_query(&msql, insert)){
		fprintf(stderr, "insert error %d:%s\n",
				mysql_errno(&msql), mysql_error(&msql));
		r = SQL_FAILED;
	}
	return r;
}

int sql_update(u_char *msisdn, u_char *msid, _Int32 mip, _Int32 gk){
	int r = 0;
	u_char update[SQL_LEN];
	sprintf(update,
			"UPDATE %s SET MSISDN='%s' WHERE MSID='%s' AND IP=%lu AND GK=%lu",
			TABLE_NAME, msisdn, msid, mip, gk);
	if(mysql_query(&msql, update)){
		fprintf(stderr, "update error %d:%s\n",
				mysql_errno(&msql), mysql_error(&msql));
		r = SQL_FAILED;
	}
	return r;
}

