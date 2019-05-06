#ifndef __DIALHP_UDT_H__
#define __DIALHP_UDT_H__

#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/prctl.h> 

#include "aes.h"
#include "udt.h"
#include "yder.h"
#include "version.h"
#include "dial.h"

int dialhp_udt_init(char *ip, int port);
void dialhp_udt_clean();
int dialhp_udt_sent(char *request);
int dialhp_udt_recv(char *response);
int dialhp_config_module();
void dialhp_config_module_clean();

extern int dialhp_stop;

#endif