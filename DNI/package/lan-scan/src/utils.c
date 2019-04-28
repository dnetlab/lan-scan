
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/timerfd.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "utils.h"

char *trim_str(char *str)
{
    char *end;

    // ltrim
    while (isspace(*str)) {
        str++;
    }

    if (*str == 0) // only spaces
        return str;

    // rtrim
    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) {
        end--;
    }

    // null terminator
    *(end + 1) = 0;

    return str;
}

int get_device_ip_mac(const char *device, uint8_t *ip, uint8_t *mac)
{
    int ret = 0;
    int sockfd = -1;
    struct ifreq ifr;
    struct sockaddr_in *addr;

    printf("device = %s\n", device);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        perror("socket");
        return -1;
    }
    
    strncpy(ifr.ifr_name, (const char *)device, sizeof(ifr.ifr_name) - 1);
    
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if(ret < 0)
    {
        perror("ioctl");
        close(sockfd);
        return -1;
    }

    addr = ((struct sockaddr_in *)&(ifr.ifr_addr));

    memcpy(ip, &(addr->sin_addr), 4);

    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret < 0)
    {
        perror("ioctl");
        close(sockfd);
        return -1;        
    }

    memcpy(mac, (uint8_t *)(ifr.ifr_hwaddr.sa_data), 6);

    close(sockfd);

    return 0;
}

#define EASY_EV_TIMER

int ev_timer_init(ev_timer_t *timer)
{
    struct itimerspec newValue;

    memset(&newValue, 0x0, sizeof(newValue));
    
    if((timer->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK)) < 0) 
    {
        fprintf(stderr, "ERROR: timerfd_settime error: %s\n", strerror(errno));
        return -1;
    }

    if (timerfd_settime(timer->fd, 0, &newValue, NULL) != 0) 
    {
        close(timer->fd);
        fprintf(stderr, "ERROR: timerfd_settime error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int ev_timer_mod(ev_timer_t *timer, cb_timer_t cb, void *arg, int timeout)
{
    struct itimerspec newValue;

    memset(&newValue, 0x0, sizeof(newValue));

    /* 为了减小复杂度，超时时间粒度目前设置为秒级 */
    newValue.it_value.tv_sec = timeout;
    //newValue.it_value.tv_nsec = 0;
    //newValue.it_interval.tv_sec = 0;
    //newValue.it_interval.tv_nsec = 0;

    if (timerfd_settime(timer->fd, 0, &newValue, NULL) != 0) 
    {
        fprintf(stderr, "ERROR: timerfd_settime error: %s\n", strerror(errno));
        return -1;
    }

    timer->cb = cb;
    timer->arg = arg;

    return 0;
}

int ev_timer_stop(ev_timer_t *timer)
{
    struct itimerspec newValue;

    memset(&newValue, 0x0, sizeof(newValue));

    if (timerfd_settime(timer->fd, 0, &newValue, NULL) != 0) 
    {
        fprintf(stderr, "ERROR: timerfd_settime error: %s\n", strerror(errno));
        return -1;
    }    

    timer->cb = NULL;
    timer->arg = NULL;

    return 0;
}

void ev_timer_destroy(ev_timer_t *timer)
{
    if(timer->fd > 0)
    {
        close(timer->fd);
    }

    timer->cb = NULL;
    timer->arg = NULL;
}

