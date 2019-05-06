#include "udt.h"
#include "aes.h"
#include "dialhp_udt.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#define MAX_BUF_SIZE 100*1024

typedef struct 
{
    int len; 
    unsigned char buf[MAX_BUF_SIZE];
} packet;

UDTSOCKET client;
const unsigned char g_key[] = {0x6d,0xaa,0xaf,0xdd,0xd2,0x2a,0x43,0x24,0x9f,0x59,0x5d,0xd5,0xc5,0xef,0xde,0x98};

int dialhp_udt_init(char *ip, int port)
{
	client = UDT::socket(AF_INET, SOCK_STREAM, 0);
	if(client <= 0)
	{
		return -1;
	}

    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &serv_addr.sin_addr);
    serv_addr.sin_port = htons(port); 
    memset(&(serv_addr.sin_zero), 0, 8);    
    
    if (UDT::ERROR == UDT::connect(client, (sockaddr*)&serv_addr, sizeof(serv_addr)))
    {
        UDT::close(client);
        y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to UDT::connect error ",__FILE__,__LINE__);
        return -1;
    }

    /* set udt send recv timeout*/
    struct timeval timeout={5,0};
    UDT::setsockopt(client, SOL_SOCKET, (UDT::SOCKOPT)SO_RCVTIMEO, (char *)&timeout,sizeof(timeout));
    UDT::setsockopt(client, SOL_SOCKET, (UDT::SOCKOPT)SO_SNDTIMEO, (char *)&timeout,sizeof(timeout));

	return 0;
}

void dialhp_udt_clean()
{
	if(client > 0)
	{
		UDT::close(client);
	}
}

static int udt_send(UDTSOCKET fd, unsigned char *msg, int len)
{
    if (len > MAX_BUF_SIZE)
    {
        y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to msg len %d is too big ",__FILE__,__LINE__,len);
        return -1;
    }
    
    packet d;
    d.len = htonl(len);
    memcpy(d.buf, msg, len);
    char *data = (char *)&d;
    
    int size = len + 4;
    int ssize = 0;
    int ss = 0;
    while (ssize < size)
    {
        if (UDT::ERROR == (ss = UDT::send(fd, data + ssize, size - ssize, 0)))
            return -1;
        ssize += ss;
    }
    return 0;
}

static int udt_recv(UDTSOCKET fd, unsigned char *dest, int size)
{
    int len = 0;
    int ret = 0;

    int rs = 0;
    if (UDT::ERROR == (rs = UDT::recv(fd, (char *)&len, 4, 0)))
        return -1;

    ret = ntohl(len);
    if (ret > size)
    {
        y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to msg len %d is too big ",__FILE__,__LINE__,len);
        return -1;
    }
    int rsize = 0;
    while (rsize < ret)
    {
        if (UDT::ERROR == (rs = UDT::recv(fd, (char *)dest + rsize, size - rsize, 0)))
            return -1;
         rsize += rs;
    }
    return ret;
}

int dialhp_udt_sent(char *request)
{
	int len;
	char src[MAX_BUF_SIZE] = {0};

	len = dialhp_aes_encode(g_key, (unsigned char *)request, strlen(request), (unsigned char *)src, MAX_BUF_SIZE);
	if (len < 0){

        y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to aes encode request failed ",__FILE__,__LINE__);
		return -1;
	}

	int ret = udt_send(client, (unsigned char *)src, len);
    if (0 != ret){

        UDT::close(client);
        return ret;
    }

	return 0;
}

int dialhp_udt_recv(char *response)
{
	int ret;
	char dest[MAX_BUF_SIZE] = {0};

	ret = udt_recv(client, (unsigned char *)dest, MAX_BUF_SIZE);
	if(ret < 0){

    	UDT::close(client);
    	return -1;
	}
	
	int len = ret;
	len = dialhp_aes_decode(g_key, (unsigned char *)dest, len, (unsigned char *)response, MAX_BUF_SIZE);
	if (len <= 0)
	{
        y_log_message(Y_LOG_LEVEL_ERROR,"[%s:%d] Failed to aes decode response failed ",__FILE__,__LINE__);
		return -1;
	}

	response[len] = '\0';

	return 0;
}


