#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <resolv.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "dns.h"
#include "dial.h"
#include "yder.h"


int create_udp_fd()
{
		int rtn = 0,fd = 0;
		struct timeval timeout;

		fd = socket(AF_INET,SOCK_DGRAM,0);
		if(fd < 0)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to %s ",__FILE__,__LINE__,__func__);
				return -1;
		}

		timeout.tv_sec = 0;
		timeout.tv_usec = 50*1000;

		rtn = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval));
		if(rtn < 0)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to %s ",__FILE__,__LINE__,__func__);
				close(fd);
				return -1;
		}

		timeout.tv_sec = 2;
		timeout.tv_usec = 0;
		rtn = setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(struct timeval));
		if(rtn < 0)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to %s ",__FILE__,__LINE__,__func__);
				close(fd);
				return -1;
		}

		return fd;
}

addr_list_t *load_server_list()
{
		json_t *info_list = NULL;
		int index = 0;
		json_t *nameserver = NULL;
		addr_list_t* srv_list = (addr_list_t*)calloc(1,sizeof(addr_list_t));

		if(json_array_size(dialhp_config.views) == 0)
		{
			y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to %s json_array_size",__FILE__,__LINE__,__func__);
			return NULL;
		}
		srv_list->cnt = json_array_size(dialhp_config.views);
		srv_list->addrs = (addr_t*) calloc(srv_list->cnt,sizeof(addr_t));

		json_array_foreach(dialhp_config.views, index, info_list){

			if(json_string_value(json_object_get(info_list, "nameserver")) == NULL){
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to %s get nameserver",__FILE__,__LINE__,__func__);
				return NULL;
			}
			strcpy(srv_list->addrs[index].addr,(char *)json_string_value(json_object_get(info_list, "nameserver")));
		}

		return srv_list;
}

void load_server_clean(addr_list_t *srv_list)
{
	if(!srv_list->addrs){

		free(srv_list->addrs);
	}
	if(!srv_list){

		free(srv_list);
	}
}

addr_list_t* do_dns_dial(const char* dname,const char* srv_addr)
{
		int rtn = 0,msglen = 0,anslen = 0,rr_cnt = 0,a_cnt = 0,i = 0;
		char msg[MAXDNAME] = {'\0'};
		char answer[MAXDNAME] = {'\0'};
		addr_list_t* addr_list = NULL;
		ns_msg handle;
		ns_rr rr;

		msglen = dns_fill_query((struct dnshdr_s *)msg,(char*)dname,((pthread_self() + 1)%0xffff),
		__cpu_to_be16(NS_FLAG_RD), __cpu_to_be16(NS_CLASS_IN),__cpu_to_be16(NS_TYPE_A));

		struct sockaddr_in addr;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(53);
		inet_pton(AF_INET,srv_addr,&addr.sin_addr.s_addr);

		int fd = create_udp_fd();
		if(fd < 0)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to create udp fd ",__FILE__,__LINE__);
				return NULL;
		}

		rtn = sendto(fd,msg,msglen,0,(const struct sockaddr *)&addr,sizeof(addr));
		if(rtn < 0)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to send dns msg ",__FILE__,__LINE__);
				close(fd);
				return NULL;
		}

		anslen = recvfrom(fd,answer,sizeof(answer),0,NULL,NULL);
		if(anslen < 0) 
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] [%s]-[%s] Failed to recv response msg ",__FILE__,__LINE__,srv_addr,dname);
				close(fd);
				return NULL;
		}

		rtn = ns_initparse((u_char*)answer,anslen,&handle);
		if(rtn < 0)
		{       
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to initparse ",__FILE__,__LINE__);
				close(fd);
				return NULL;
		}

		rr_cnt = ns_msg_count(handle,ns_s_an);
		if(rr_cnt <= 0)
		{
				y_log_message(Y_LOG_LEVEL_DEBUG,"[%s:%d] [%s]-[%s] recv msg no answer ",__FILE__,__LINE__,srv_addr,dname);
				close(fd);
				return NULL;
		}

		addr_list = (addr_list_t*)calloc(1,sizeof(addr_list_t));
		addr_list->addrs = (addr_t*)calloc(rr_cnt,sizeof(addr_t));

		for(i = 0 ; i < rr_cnt ; i++)
		{
				ns_parserr(&handle,ns_s_an,i,&rr);

				if(ns_rr_type(rr) == ns_t_a)
				{
						inet_ntop(AF_INET,ns_rr_rdata(rr),addr_list->addrs[a_cnt].addr,IP_SIZE);
						//y_log_message(Y_LOG_LEVEL_DEBUG,"[%s:%d] %s->%s->%s",__func__,__LINE__,srv_addr,dname,addr_list->addrs[a_cnt].addr);
						a_cnt++;
				}
		}
		addr_list->cnt = a_cnt;
		
		close(fd);
		return addr_list;
}





