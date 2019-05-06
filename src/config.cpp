#include <time.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <sys/time.h>
#include <jansson.h>
#include <pthread.h>
#include "dialhp_udt.h"

#define DIALHP_UDT_VERSION "1.0"
#define DIALHP_CONFIG_LIMIT 1000

pthread_t ycloud_config_module_tid;
pthread_t ycloud_report_module_tid;

dialhp_config_t dialhp_config;
json_t *config_fd = NULL;
bool dialhp_udt_socket_ok = false;

static int dialhp_config_init(const char *filepath)
{
	json_error_t error ;
	json_t *download = NULL;
	json_t *views    = NULL;
	json_t *server   = NULL;

	config_fd = json_load_file(filepath, 0, &error);
    if(config_fd == NULL) 
    {
        y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] [%d:%d] %s",__FILE__,__LINE__,error.line,error.column,error.text);
        return -1;
    }

    views = json_object_get(config_fd, "views");
    if(views == NULL){

    	y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Fial to get config views",__FILE__,__LINE__);
    	return -1;
    }
    dialhp_config.views = (json_t *)views;

    server = json_object_get(config_fd, "server");
    if(server == NULL){

    	y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Fial to get config server",__FILE__,__LINE__);
    	return -1;
    }

    if(json_string_value(json_object_get(server, "node")) == NULL)
    {
    	y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Fial to get config server node",__FILE__,__LINE__);
    	return -1;
    }
    dialhp_config.server_node = (char *)json_string_value(json_object_get(server, "node"));
    dialhp_config.server_device = (char *)json_string_value(json_object_get(server, "device"));

    download = json_object_get(config_fd, "download");
    if(download == NULL){

    	y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Fial to get config download",__FILE__,__LINE__);
    	return -1;
    }

    if((json_string_value(json_object_get(download, "host")) == NULL) &&
    	(json_integer_value(json_object_get(download, "port")) == 0))
    {
    	y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Fial to get config download host port",__FILE__,__LINE__);
    	return -1;
    }
    dialhp_config.download_host = (char *)json_string_value(json_object_get(download, "host"));
    dialhp_config.download_port = json_integer_value(json_object_get(download, "port"));

    dialhp_config.config_version = 0;
    memset(dialhp_config.snapShot, 0 ,20);
    dialhp_config.heartbeat = 3;

    y_log_message(Y_LOG_LEVEL_DEBUG,"Success to load config file !");

	return 0;
} 

static void dialhp_config_clean()
{
	json_decref(config_fd);
}

static void dialhp_get_localtime(char *date_stamp)
{
    time_t date;
    struct tm *tm_stamp;
    char stamp[20];
    memset(date_stamp,0,20);

    time(&date);
    tm_stamp = localtime (&date);
    strftime (stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", tm_stamp);

    strcpy(date_stamp, stamp);
}

static void dialhp_signature(char *date_stamp, char *requestJSON, char *signature)
{
    char *signature_str = NULL;
    MD5_CTX ctx;  
    char signing_key[] = "ms^123456";
    char requestJSON100[101];
    unsigned char md[16];  
    char tmp[3]={};  
    int i;  

    memset(signature, 0, 33);
    signature_str = (char *)malloc(strlen(date_stamp) + strlen(signing_key) + 100 + 1);

    memset(requestJSON100, 0, 101);
    memcpy(requestJSON100, requestJSON, 100);
    strcpy(signature_str,date_stamp);
    strcat(signature_str,signing_key);
    strcat(signature_str,requestJSON100);

    MD5_Init(&ctx);  
    MD5_Update(&ctx,signature_str,strlen(signature_str));  
    MD5_Final(md,&ctx);  

    for( i=0; i<16; i++ ){  
        sprintf(tmp,"%02x",md[i]);  
        strcat(signature,tmp);  
    } 

    free(signature_str);
}

/*
request : {"action":"download",
		   "content":{"src":"dialdns@hijack",
		   			  "dest":"msconfig",
		   			  "version":"1.0",
		   			  "request":{"action":"ConfigDownload",
		   			  			 "seqno":"1111",
		   			  			 "requestJSON":{"startVersion":0,
		   			  			 				"snapShot":"",
		   			  			 				"limit":1000
		   			  			 				}
		   			  			 }
		   			   }
		    }

*/

static int get_config_info_from_dms(json_t *json_body)
{

	int ret = 0;
	char *request_str = NULL;
	char response[100 * 1024];
	char date_stamp[20];
	char signature[33];
	char *requestJSON = NULL;
	char src[40];
	memset(src, 0, 40);
	strcpy(src,"dialdns@");
	strcat(src,dialhp_config.server_node);
	
	const char *version      = DIALHP_UDT_VERSION;
	json_t *dialhp_config_info = NULL;
	json_error_t error;
	json_t *requestJSON_body = json_object();
	json_object_set_new(requestJSON_body, "startVersion",json_integer(dialhp_config.config_version));
	json_object_set_new(requestJSON_body, "snapShot",json_string(dialhp_config.snapShot));
	json_object_set_new(requestJSON_body, "limit",json_integer(DIALHP_CONFIG_LIMIT));
	
	requestJSON = json_dumps(requestJSON_body, JSON_COMPACT);
	dialhp_get_localtime(date_stamp);
	dialhp_signature(date_stamp, requestJSON, signature);
	 	
	json_t *request = json_object();
	json_object_set_new(request, "action",json_string("ConfigDownload"));
	json_object_set_new(request, "seqno",json_integer(1111));
	json_object_set_new(request, "timestamp",json_string(date_stamp));
	json_object_set_new(request, "signature",json_string(signature));
	json_object_set_new(request, "requestJSON",requestJSON_body);

	json_t *content = json_object();
	json_object_set_new(content, "src",json_string(src));
	json_object_set_new(content, "dest",json_string("msconfig"));
	json_object_set_new(content, "version",json_string(version));
	json_object_set_new(content, "request",request);

	json_t *request_JSON = json_object();
	json_object_set_new(request_JSON, "action",json_string("download"));
	json_object_set_new(request_JSON, "content",content);

	request_str = json_dumps(request_JSON, JSON_COMPACT);
	//printf("request : %s\n", request_str);

	if(dialhp_udt_sent(request_str) != 0){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp udt sent",__FILE__,__LINE__);
		ret = -1;
		goto error;
	}

	memset(response, 0,100 * 1024);
	if(dialhp_udt_recv(response) != 0){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp udt recv",__FILE__,__LINE__);
		ret = -1;
		goto error;
	}

	dialhp_config_info = json_loads(response, 0, &error);
    if(dialhp_config_info == NULL) 
    {
        y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] [%d:%d] %s",__FILE__,__LINE__,error.line,error.column,error.text);
        ret = -1;
        goto error;
    }

    json_object_update(json_body,dialhp_config_info);

	error:
		json_decref(requestJSON_body);
		json_decref(request);
		json_decref(content);
		json_decref(request_JSON);

	return ret;
}

/*
{
     "action": "ConfigDownload",
     "responseJSON": {
          "items": [
               {
                    "bt": "dialdns",
                    "content": {
                         "dialPolicy": {
                              "interval": 60
                         },
                         "targetName": "www.baidu.com",
                         "targetType": "A",
                         "taskId": 123
                    },
                    "hashCode": 1,
                    "md5Key": "112233333333",
                    "operation": "add",
                    "sbt": "hijackTask",
                    "version": 16
               }
          ],
          "version": {
               "end": 16,
               "snapShot": null,
               "start": 0
          }
     },
     "seqno": 1111,
     "signature": "a4a84f08fa843bd502038e1a009d7ef6",
     "timestamp": "2018-05-22 14:24:26"
}

*/
static void add_operation_to_hash(int taskId, const char *targetName, const char *targetType, int interval)
{
	//y_log_message(Y_LOG_LEVEL_DEBUG,"add :%d %s %s %d", taskId, targetName, targetType, interval);
	std::string taskId_tmp;
	char taskId_str[16] = {0};
	dial_node_t dial_node;

	sprintf(taskId_str,"%d",taskId);
	strcpy(dial_node.dname,targetName);
	dial_node.taskId = taskId;
	dial_node.interval = interval;
	taskId_tmp.assign(taskId_str);
	gettimeofday(&dial_node.t_start,NULL);
	dial_map[taskId_tmp] = dial_node;
}

static void del_operation_to_hash(int taskId)
{
	//y_log_message(Y_LOG_LEVEL_DEBUG,"del : %d", taskId);
	std::string taskId_tmp;
	char taskId_str[16] = {0};

	sprintf(taskId_str,"%d",taskId);
	taskId_tmp.assign(taskId_str);
    dial_map.erase(taskId_tmp);  
}

static int config_items_write_hash(json_t *items)
{
	//printf("%s\n", json_dumps(items, 5) );
	int index			= 0;
	int taskId 			= 0;
	int interval 		= 0;
	const char *operation 	= NULL;
	const char *targetType 	= NULL;
	const char *targetName 	= NULL;
	json_t *content		= NULL;
	json_t *dialPolicy	= NULL;
	json_t *item 		= NULL;

	pthread_mutex_lock(&dial_map_lock);
	json_array_foreach(items, index, item){

		operation = json_string_value(json_object_get(item, "operation"));
		if(strcmp(operation, "add") == 0){

			content = json_object_get(item, "content");
			taskId = json_integer_value(json_object_get(content, "taskId"));
			targetName = json_string_value(json_object_get(content, "targetName"));
			targetType = json_string_value(json_object_get(content, "targetType"));
			dialPolicy = json_object_get(content, "dialPolicy");
			interval = json_integer_value(json_object_get(dialPolicy, "interval"));
			add_operation_to_hash(taskId, targetName, targetType, interval);

		}else if(strcmp(operation, "delete") == 0){

			content = json_object_get(item, "content");
			taskId = json_integer_value(json_object_get(content, "taskId"));
			del_operation_to_hash(taskId);

		}else{

			y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to unknown operation %s",__FILE__,__LINE__,operation);
			pthread_mutex_unlock(&dial_map_lock);
			return -1;
		}
	}
	pthread_mutex_unlock(&dial_map_lock);

	return 0;
}

static int config_info_write_hash(json_t *json_body)
{
	//printf("%s\n", json_dumps(json_body, 5));
	json_t *content = NULL;
	json_t *responseJSON = NULL;
	json_t *version = NULL;
	json_t *items = NULL;
	json_error_t error;
	int end_version = 0;

	content = json_loads(json_string_value(json_object_get(json_body,"content")), 0, &error);
	if(content == NULL){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] [%d:%d] %s",__FILE__,__LINE__,error.line,error.column,error.text);
      	return -1;
	}

	responseJSON = json_object_get(content,"responseJSON");
	if(responseJSON == NULL){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to get responseJSON",__FILE__,__LINE__);
    	return -1;
	} 

	version = json_object_get(responseJSON,"version");
	if(version == NULL){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to get version",__FILE__,__LINE__);
    	return -1;
	} 

	items = json_object_get(responseJSON,"items");
	if(items == NULL){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to get items",__FILE__,__LINE__);
    	return -1;
	} 

	if(config_items_write_hash(items) != 0){

        y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to config items write_hash",__FILE__,__LINE__);
		return -1;
	}

	if(json_string_value(json_object_get(version,"snapShot")) != NULL){

		strcpy(dialhp_config.snapShot, json_string_value(json_object_get(version, "snapShot")));
	}

	end_version = atoi(json_string_value(json_object_get(version,"end")));

	dialhp_config.config_version = end_version;
	return 0;
}

static int dialhp_request_update_new_config(int msConfigVersion)
{
	int ret = 0;
	json_t *json_body = json_object();

	do{
		if(get_config_info_from_dms(json_body) != 0)
        {
            y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to get domain config info",__FILE__,__LINE__);
            ret = -1;
            goto error;
        }
       
        if(config_info_write_hash(json_body) != 0)
        {
           y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to config info write redis",__FILE__,__LINE__);
            ret = -1;
            goto error;
        }

	}while(dialhp_config.config_version < msConfigVersion);

error:
	json_decref(json_body);
	memset(dialhp_config.snapShot, 0 , 20);

	return ret;
}

/*
 {"action":"download",
  "content":"{\"action\":\"HeartBeat\",
  			  \"responseJSON\":{\"configSignature\":\"2018-04-13 17:45:02.126896+08\",\"msConfigVersion\":\"87\"},
  			  \"seqno\":11111,
  			  \"signature\":\"47796b3686f62106815578be45a17da0\",
  			  \"timestamp\":\"2018-05-22 10:52:25\"}",
  "error":null}
*/
static int dialhp_handle_heartbeat_data(char * response)
{
	//printf("response : %s\n", response);

	int ret = 0;
	int msConfigVersion = 0;
	json_t *response_json = NULL;
	json_t *content = NULL;
	json_t *responseJSON = NULL;
	json_error_t error;

	response_json = json_loads(response, 0, &error);
	if(response_json == NULL){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] [%d:%d] %s",__FILE__,__LINE__,error.line,error.column,error.text);
        ret = -1;
        goto error;
	}

	if(json_string_value(json_object_get(response_json,"content")) == NULL){
			
		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to  %s",__FILE__,__LINE__,response);
        ret = -1;
        goto error;
	
	}

	content = json_loads(json_string_value(json_object_get(response_json,"content")), 0, &error);
	if(content == NULL){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] [%d:%d] %s",__FILE__,__LINE__,error.line,error.column,error.text);
        ret = -1;
        goto error;
	}

	responseJSON = json_object_get(content,"responseJSON");
	msConfigVersion = atoi(json_string_value(json_object_get(responseJSON,"msConfigVersion")));

	if(dialhp_config.config_version < msConfigVersion)  
    { 
        if(dialhp_request_update_new_config(msConfigVersion) != 0)
        {
			y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp update new config ",__FILE__,__LINE__);
            ret = -1;
        	goto error;
        }

        y_log_message(Y_LOG_LEVEL_DEBUG,"msConfigVersion ：%d dialhp update new config success !", msConfigVersion);
    }

	error: 
		json_decref(response_json);

	return ret;
}

void *dialhp_ycloud_config_handler(void *arg)
{
	/*set pthread name*/
	char tname[16];  
    memset(tname, 0, 16);  
    snprintf(tname, 16, "dialhp_config");  
    prctl(PR_SET_NAME, tname); 

	char *request_str = NULL;
	char response[1024];
	char date_stamp[20];
	char signature[33];
	char *requestJSON = NULL;
	char src[40];
	memset(src, 0, 40);
	strcpy(src,"dialdns@");
	strcat(src,dialhp_config.server_node);
	static int error_count = 0;
	const char *version      	= DIALHP_UDT_VERSION;
	const char *softwareVersion = VERSION;

again:
	while(!dialhp_stop){

		if(dialhp_udt_init(dialhp_config.download_host, dialhp_config.download_port) != 0){

			dialhp_udt_clean();
			y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp udt init %s:%d ",__FILE__,__LINE__,
				dialhp_config.download_host, dialhp_config.download_port);

			sleep(3);
			dialhp_udt_socket_ok = false;
			continue;
		}

		break;
	}
	
	y_log_message(Y_LOG_LEVEL_DEBUG,"Success to starting dialhp ycloud config handler !");

	dialhp_udt_socket_ok = true;

	while(!dialhp_stop){

	    json_t *requestJSON_body = json_object();
	    json_object_set_new(requestJSON_body, "softwareVersion",json_string(softwareVersion));
	    json_object_set_new(requestJSON_body, "configVersion",json_integer(dialhp_config.config_version));
	    
	    //formatted json to string
	    requestJSON = json_dumps(requestJSON_body, JSON_COMPACT);
	    dialhp_get_localtime(date_stamp);
	    dialhp_signature(date_stamp, requestJSON, signature);

	    json_t *request = json_object();
	    json_object_set_new(request, "action",json_string("HeartBeat"));
	    json_object_set_new(request, "seqno",json_integer(1111));
	    json_object_set_new(request, "timestamp",json_string(date_stamp));
	    json_object_set_new(request, "signature",json_string(signature));
	    json_object_set_new(request, "requestJSON",requestJSON_body);

	    json_t *content = json_object();
	    json_object_set_new(content, "src",json_string(src));
	    json_object_set_new(content, "dest",json_string("msconfig"));
	    json_object_set_new(content, "version",json_string(version));
	    json_object_set_new(content, "request",request);

	    json_t *request_JSON = json_object();
	    json_object_set_new(request_JSON, "action",json_string("download"));
	    json_object_set_new(request_JSON, "content",content);
	    
	    request_str = json_dumps(request_JSON, JSON_COMPACT);
	    //printf("request : %s\n", request_str);

		if(dialhp_udt_sent(request_str) != 0){

			y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp udt sent ",__FILE__,__LINE__);
			error_count ++;
			if(error_count >= 3){

				json_decref(requestJSON_body);
				json_decref(request);
				json_decref(content);
				json_decref(request_JSON);
				error_count = 0;
				dialhp_udt_socket_ok = false;
				y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] line again udt socket ",__FILE__,__LINE__);
				goto again;
			}else{
				goto error;
			}
		}

		error_count = 0;
		memset(response, 0, 1024);
		if(dialhp_udt_recv(response) != 0){

			y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp udt recv",__FILE__,__LINE__);
			goto error;
		}

		if(dialhp_handle_heartbeat_data(response) != 0){

			y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp handle heartbeat data",__FILE__,__LINE__);
			goto error;
		}

	error:
		json_decref(requestJSON_body);
		json_decref(request);
		json_decref(content);
		json_decref(request_JSON);

		sleep(dialhp_config.heartbeat);
	}

	return ((void *)0);
}

static int dialhp_log_send_to_dms(json_t *upload)
{
	//y_log_message(Y_LOG_LEVEL_DEBUG,"report data %s",json_dumps(upload,5));

	char *upload_str = NULL;
	upload_str = (char *)json_dumps(upload,JSON_COMPACT);
	char response[1024];

	if(dialhp_udt_sent(upload_str) != 0){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp udt sent log",__FILE__,__LINE__);
		return -1;
	}

	memset(response, 0, 1024);
	if(dialhp_udt_recv(response) != 0){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp udt recv log",__FILE__,__LINE__);
		return -1;
	}

	y_log_message(Y_LOG_LEVEL_DEBUG,"DMS return %s", response);
	return 0;
}

static void *dialhp_ycloud_report_handler(void *arg)
{
	/*set pthread name*/
	char tname[16];  
    memset(tname, 0, 16);  
    snprintf(tname, 16, "dialhp_report");  
    prctl(PR_SET_NAME, tname);

    y_log_message(Y_LOG_LEVEL_DEBUG,"Success to starting dialhp ycloud report handler !");

	time_t httpdns_time_satrt   = 0;
    time_t httpdns_time_end     = 0;
    json_t *upload = json_object();
    json_t *content = json_object();
    json_t *events  = json_object();
    json_t *array  = json_array();
    std::string node;

	httpdns_time_satrt = time(NULL);    
    while(!dialhp_stop){

    	if(!dialhp_udt_socket_ok){
    		
    		sleep(3);
    		continue;
    	}

    	if((difftime(httpdns_time_end, httpdns_time_satrt) < 60)){
    	 	/*write json*/
    	 	pthread_mutex_lock(&result_queue_lock);
            if(result_queue.empty())
            { 
                pthread_mutex_unlock(&result_queue_lock);
                sleep(1);
            }else{

	            node = result_queue.front();
	            result_queue.pop();
	            json_array_append_new(array, json_string(node.c_str()));
	            pthread_mutex_unlock(&result_queue_lock);
        	}

    	}else{
    		/*log report*/
    		json_object_set_new(upload, "action", json_string("upload"));
    		json_object_set_new(events, "events", array);
    		json_object_set_new(upload, "content", events);
    		if(dialhp_log_send_to_dms(upload) != 0){
    			y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp log send to dms",__FILE__,__LINE__);
    		}

    		httpdns_time_satrt = time(NULL);
    		json_decref(events);
    		json_decref(upload);
    		json_decref(content);
    		json_decref(array);
    		upload = json_object();
    		events = json_object();
    		content = json_array();
    		array  = json_array();
    	}

    	httpdns_time_end = time(NULL);
    }

    json_decref(events);
    json_decref(upload);
    json_decref(content);
    json_decref(array);
	return ((void *)0);
}


int dialhp_config_module()
{

	if(dialhp_config_init(DIALHP_CONFIG_FILE) != 0){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to dialhp config init [%s]",__FILE__,__LINE__,DIALHP_CONFIG_FILE);
        return -1;
	}

    if (pthread_create(&ycloud_config_module_tid, NULL, dialhp_ycloud_config_handler, NULL) !=0){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to create pthread for dialhp config handler ",__FILE__,__LINE__);
        return -1;
    }

    if (pthread_create(&ycloud_report_module_tid, NULL, dialhp_ycloud_report_handler, NULL) !=0){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to create pthread for dialhp report handler ",__FILE__,__LINE__);
        return -1;
    }

    return 0;
}

void dialhp_config_module_clean()
{
	void * result;
    if(pthread_join(ycloud_config_module_tid, &result) == -1){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to create pthread for dialhp config handler clean ",__FILE__,__LINE__);
    }

    if(pthread_join(ycloud_report_module_tid, &result) == -1){

		y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to create pthread for dialhp report handler clean ",__FILE__,__LINE__);
    }

    dialhp_config_clean();
}

#if 0
int main(int argc, char const *argv[])
{
	dialhp_ycloud_config_handler();
	dialhp_udt_clean();
	return 0;
}
#endif
