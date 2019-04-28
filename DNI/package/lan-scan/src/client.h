
#ifndef __CLIENT_H_
#define __CLIENT_H_

#include "list.h"

typedef struct {
    struct list_head list;
    char ipaddr[16];
    char macaddr[18];
    char hostname[65];
    int status;
    int uptime;
    int offtime;
    char device[20];
} lan_client_t;


#endif
