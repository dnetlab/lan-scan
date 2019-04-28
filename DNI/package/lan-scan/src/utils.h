
#ifndef __UTILS_H_
#define __UTILS_H_

#define PID_FILE "/var/run/lan-scan.pid"

struct ev_timer;

/* 简单定时器 */
typedef int (*cb_timer_t)(struct ev_timer *);

typedef struct ev_timer {
    int fd;
    cb_timer_t cb;
    void *arg;
} ev_timer_t;

int ev_timer_init(ev_timer_t * timer);
int ev_timer_mod(ev_timer_t * timer, cb_timer_t cb, void * arg, int timeout);
int ev_timer_stop(ev_timer_t * timer);
void ev_timer_destroy(ev_timer_t * timer);

char *trim_str(char *str);
int get_device_ip_mac(const char *device, uint8_t *ip, uint8_t *mac);

#endif
