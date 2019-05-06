#include <stdio.h>
#include <string.h>
#include <string>
#include <queue>
#include <map>
#include <pthread.h>
#include <signal.h>
#include "dial.h"
#include "thread.h"
#include "version.h"
#include "dialhp_udt.h"
#include <clib/daemon.h>
#include "yder.h"

pthread_mutex_t dial_queue_lock;
std::queue<dial_node_t> dial_queue;

pthread_mutex_t result_queue_lock;
std::queue<std::string> result_queue;

pthread_mutex_t dial_map_lock;
std::map<std::string,dial_node_t> dial_map;

threadpool_t dial_tp;
int dialhp_stop = 0;
addr_list_t *srv_list;

static void sigint_handler(int signal_number)
{
    dialhp_stop = 1;
}

bool parse_arg(int argc,char**argv)
{
		if(2 != argc)
		{
				printf("error param:%s\n",argv[1]);
				printf("please use dialhp |-s|-k|-r|-v|-g|\n",argv[1]);
				exit(0);
		}
		if(!strcmp("-s", argv[1])) 
		{   
				return true;		
		}    
		else if (!strcmp("-r", argv[1])) 
		{    
				daemon_stop();
				return true;		
		}    
		else if (!strcmp("-k", argv[1])) 
		{    
				daemon_stop();
				exit(0);
		}    
		else if (!strcmp("-g", argv[1])) 
		{    
				return false;		
		}    
		else if(!strcmp("-v", argv[1]))
		{    
				printf("dialhp version:%s\n",VERSION);
				exit(0);
		}    
		else 
		{    
				printf("unkown param:%s\n",argv[1]);
				printf("please use |-s|-k|-r|-v|-g|\n",argv[1]);
				exit(0);
		}    
}

bool lock_init()
{
		int rtn = 0;
		rtn = pthread_mutex_init(&dial_queue_lock,NULL);
		if(0 != rtn)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to g_lock init ",__FILE__,__LINE__);
				return false;
		}
		pthread_mutex_init(&result_queue_lock,NULL);
		if(0 != rtn)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to g_lock init ",__FILE__,__LINE__);
				return false;
		}
		pthread_mutex_init(&dial_map_lock,NULL);
		if(0 != rtn)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to g_lock init ",__FILE__,__LINE__);
				return false;
		}
		return true;
}

int main(int argc,char**argv)
{
		struct sigaction sigint_action;

		memset (&sigint_action, 0, sizeof (sigint_action));
		sigint_action.sa_handler = sigint_handler;
		sigint_action.sa_flags = SA_RESETHAND;
		sigaction (SIGINT, &sigint_action, NULL);

		int rtn = 0;
		pthread_t monitor_tid = 0;
		bool deamon = parse_arg(argc,argv);
		if(deamon)
		{
				daemon_start(1);
		}
		
		if(y_init_logs("dialhp",Y_LOG_MODE_CONSOLE|Y_LOG_MODE_FILE ,Y_LOG_LEVEL_DEBUG,DIALHP_LOG_FILE, NULL) != 1)
    	{
	        printf("Failed to y_init_logs [%s]\n",DIALHP_LOG_FILE);
	        return -1;
    	}

		if(dialhp_config_module() != 0){

			y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp config module ",__FILE__,__LINE__);
			return -1;
		}

		if(false == lock_init())
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp g_lock init ",__FILE__,__LINE__);
				return -1;
		}

		srv_list = load_server_list();
		if(!srv_list)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to load server list ",__FILE__,__LINE__);
				return -1;
		}
		
		rtn = threadpool_init(&dial_tp,THREAD_NUM);		
		if(-1 == rtn)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to threadpool init ",__FILE__,__LINE__);
				return -1;
		}
		
		rtn = pthread_create(&monitor_tid,NULL,monitor_dialmap_thread,NULL);
		if(0 != rtn)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to create monitor thread ",__FILE__,__LINE__);
				return -1;
		}
		
		rtn = pthread_join(monitor_tid,NULL);
		if(0 != rtn)
		{
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to join monitor thread ",__FILE__,__LINE__);
				return -1;
		}

		threadpool_destroy(&dial_tp);
		dialhp_config_module_clean();
		load_server_clean(srv_list);
		y_log_message(Y_LOG_LEVEL_DEBUG, "dialhp over");
		y_close_logs();
	
		return 0;
}

