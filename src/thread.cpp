#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string>
#include "thread.h"
#include "dial.h"
#include "yder.h"

#define RES_BUF_SIZE 1024

void get_date(char*batchno)
{
		time_t          timep;
		struct tm       st_tm;
		time(&timep);
		localtime_r(&timep, &st_tm);
		sprintf((char *)batchno, "%02d%02d%02d%02d%02d%02d",
						(1900 + st_tm.tm_year),
						(1 + st_tm.tm_mon),
						st_tm.tm_mday,
						st_tm.tm_hour,
						st_tm.tm_min,
						st_tm.tm_sec);
}

void push_to_res_queue(dial_node_t & task_node,addr_list_t* rr_list,char* srv)
{
		int i = 0;
		char res_buf[RES_BUF_SIZE] = {'\0'};
		char ip_list[RES_BUF_SIZE] = {'\0'};
		char time_buf[20] = {'\0'};
		get_date(time_buf);

		if(rr_list)
		{
				for(i = 0 ; i < rr_list->cnt ; i++)
				{
						strcat(ip_list,rr_list->addrs[i].addr);
						if(i == rr_list->cnt-1)
						{
								break;
						}
						strcat(ip_list,",");
				}

				sprintf(res_buf,"%s||%d|%s|A||%s|%s|%d|%s",dialhp_config.server_node,task_node.taskId,task_node.dname,srv,ip_list,task_node.interval,time_buf);
				free(rr_list->addrs);
				free(rr_list);
		}
		else
		{
				sprintf(res_buf,"%s||%d|%s|A||%s||%d|%s",dialhp_config.server_node,task_node.taskId,task_node.dname,srv,task_node.interval,time_buf);
		}

		y_log_message(Y_LOG_LEVEL_DEBUG,"[%s:%d] %s ",__func__,__LINE__,res_buf);

		std::string result(res_buf);

		pthread_mutex_lock(&result_queue_lock);
		result_queue.push(result);
		pthread_mutex_unlock(&result_queue_lock);

}

#define CMP_TIME(x,y)  ((x.tv_sec * 1000*1000 + x.tv_usec) - (y.tv_sec * 1000*1000 + y.tv_usec))

void * monitor_dialmap_thread(void *arg)
{
		extern threadpool_t dial_tp;
		std::map<std::string,dial_node_t>::iterator iter;
		struct timeval t_now;

		while(!dialhp_stop)
		{
				pthread_mutex_lock(&dial_map_lock);

				for(iter = dial_map.begin() ; iter != dial_map.end() ; iter++)
				{
						gettimeofday(&t_now,NULL);
						if(CMP_TIME(t_now,iter->second.t_start) >= 0)
						{
								t_now.tv_sec += iter->second.interval;
								iter->second.t_start = t_now;

								pthread_mutex_lock(&dial_queue_lock);
								dial_queue.push(iter->second);
								pthread_mutex_unlock(&dial_queue_lock);

								if(dial_tp.threads_used < dial_tp.act_threads_num)
								{
										pthread_cond_signal(&dial_tp.cond);	
								}
						}
				}

				pthread_mutex_unlock(&dial_map_lock);

				sleep(1);
		}
}


void * threadpool_worker_thread(void *arg)
{
		threadpool_t *tp = (threadpool_t *)arg;
		int i = 0;
		dial_node_t task_node;
		addr_list_t * res_list = NULL;

		while(tp->run_flag) 
		{
				pthread_mutex_lock(&tp->mutex);
				pthread_cond_wait(&tp->cond,&tp->mutex);
				pthread_mutex_unlock(&tp->mutex);

				if (!tp->run_flag) 
				{
						break;
				}

				pthread_mutex_lock(&tp->lock);
				tp->threads_used++;
				pthread_mutex_unlock(&tp->lock);

				while(!dial_queue.empty()) 
				{
						pthread_mutex_lock(&dial_queue_lock);
						if(dial_queue.empty())
						{
								pthread_mutex_unlock(&dial_queue_lock);
								break;
						}
						memset(&task_node,0,sizeof(dial_node_t));
						task_node = dial_queue.front();
						dial_queue.pop();
						pthread_mutex_unlock(&dial_queue_lock);

						if(!tp->run_flag)
						{
								break;
						}

						for(i = 0 ; i < srv_list->cnt ; i++)
						{
								res_list = do_dns_dial(task_node.dname,srv_list->addrs[i].addr);
								push_to_res_queue(task_node,res_list,srv_list->addrs[i].addr);
						}		
				}

				pthread_mutex_lock(&tp->lock);
				tp->threads_used--;
				pthread_mutex_unlock(&tp->lock);

		}

		pthread_mutex_lock(&tp->lock);
		tp->act_threads_num--;
		pthread_mutex_unlock(&tp->lock);
		
		return NULL;
}


int threadpool_init(threadpool_t *tp,int hope_threads_num)
{

		int i = 0;
		int ret = 0;

		tp->hope_threads_num = hope_threads_num;
		tp->threads_used = 0;
		tp->worker_thread_ids = (pthread_t *)calloc(hope_threads_num,sizeof(pthread_t));
		tp->run_flag = true;
		tp->act_threads_num = 0;

		if ((ret = pthread_mutex_init(&tp->mutex,NULL))!=0) 
		{
				return ret;
		}	
		if ((ret = pthread_mutex_init(&tp->lock,NULL))!=0) 
		{
				return ret;
		}	
		if ((ret = pthread_cond_init(&tp->cond,NULL))!=0) 
		{
				return ret;
		}	

		for(i=0;i<hope_threads_num;i++)
		{

				if ((ret = pthread_create(&tp->worker_thread_ids[i],NULL,threadpool_worker_thread,tp))!=0) 
				{
						return ret;
				}
				tp->act_threads_num++;
		}

		return 0;

}


int threadpool_destroy(threadpool_t *tp)
{
		int i = 0;
		tp->run_flag = false;

		pthread_cond_broadcast(&tp->cond);

		for(i = 0 ; i < tp->hope_threads_num ; i++)
		{
				pthread_join(tp->worker_thread_ids[i],NULL);
		}

		free(tp->worker_thread_ids);
		return 0;
}









