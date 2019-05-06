#ifndef _THREAD_H_
#define _THREAD_H_

#include <pthread.h>

#define THREAD_NUM 10

typedef struct threadpool 
{
	int hope_threads_num;	
	int act_threads_num;	
	volatile int threads_used;	
	bool run_flag;		
	pthread_t *worker_thread_ids;
	pthread_mutex_t mutex,lock;
	pthread_cond_t cond;

}threadpool_t;

void *monitor_dialmap_thread(void *tp);

void *threadpool_worker_thread(void *tp);

int threadpool_destroy(threadpool_t *tp);

int threadpool_init(threadpool_t *tp,int hope_threads_num);


#endif

