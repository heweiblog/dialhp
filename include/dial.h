#ifndef _DIAL_H_
#define _DIAL_H_

#include <arpa/nameser.h>
#include <jansson.h>
#include <queue>
#include <string>
#include <map>
#include "dialhp_udt.h"

#define IP_SIZE 20
#define DIALHP_CONFIG_FILE "/etc/dialhp/dialhp.json"
#define DIALHP_LOG_FILE "/var/log/dialhp/dialhp.log"

typedef struct dial_node
{
		char dname[MAXDNAME];
		int interval;
		struct timeval t_start;
		int taskId;

}dial_node_t;

typedef struct addr
{
		char addr[IP_SIZE];

}addr_t;

typedef struct addr_list
{
		int cnt;
		addr_t* addrs;		

}addr_list_t;

typedef struct dialhp_config
{
	char *download_host;
	int download_port;
	char *server_node;
	char *server_device;
	int heartbeat;
	
	int config_version;
	char snapShot[20]; 

	json_t *views;
}dialhp_config_t;

extern dialhp_config_t dialhp_config;
extern addr_list_t *srv_list;
extern pthread_mutex_t dial_queue_lock;
extern std::queue<dial_node_t>dial_queue;
extern pthread_mutex_t dial_map_lock;
extern std::map<std::string,dial_node_t> dial_map;
extern pthread_mutex_t result_queue_lock;
extern std::queue<std::string>result_queue;

addr_list_t* load_server_list();
void load_server_clean(addr_list_t *srv_list);
addr_list_t* do_dns_dial(const char* dname,const char* srv_addr);

#endif
