
/*
 * 1.直接定期获取/proc/net/arp信息,有老化时间
 * 2.获取dhcpd信息，hostname相关，获取不到，通过nbns协议获取
 * 3.获取的同时发送arp_request,检查有没有在线，会阻塞一段时间,暂定1s吧
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

#include "client.h"
#include "packet.h"
#include "utils.h"
#include "adapter.h"

int g_nbt_sock = -1;
int g_arp_sock = -1;
int g_sig_usr1 = 0;
int g_sig_usr2 = 0;
int g_sig_exit = 0;

ev_timer_t g_arp_timer;
ev_timer_t g_scan_timer;

struct list_head client_list_head;

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

static struct arp_sock lan_arps[MAX_LAN_NUM] = {
    {
        .sockfd = -1, 
        .device = "br0",
    }, {
        .sockfd = -1, 
        .device = "br1",
    }, {
        .sockfd = -1, 
        .device = "br2",
    }, {
        .sockfd = -1, 
        .device = "br3",
    }
};

/* 更新时间 */
void reset_client_status()
{
    lan_client_t *item;

    list_for_each_entry(item, &client_list_head, list);
    {
        item->status = 0;
        item->offtime = time(NULL);
    }
}

lan_client_t *find_client_by_mac(char *macaddr)
{
    lan_client_t *item = NULL;

    list_for_each_entry(item, &client_list_head, list)
    {
        if(strcmp(item->macaddr, macaddr) == 0)
        {
            return item;
        }
    }

    return NULL;
}

lan_client_t *find_client_by_ip(char *ipaddr)
{
    lan_client_t *item = NULL;

    list_for_each_entry(item, &client_list_head, list)
    {
        if(strcmp(item->ipaddr, ipaddr) == 0)
        {
            return item;
        }
    }

    return NULL;
}

lan_client_t *client_item_new()
{
    lan_client_t *item = NULL;

    item = (lan_client_t *)malloc(sizeof(lan_client_t));
    if(!item)
    {
        return NULL;
    }

    memset(item, 0x0, sizeof(lan_client_t));

    INIT_LIST_HEAD(&item->list);

    return item;
}

void client_item_free(lan_client_t *item)
{
    free(item);
}

void client_list_destroy()
{
    lan_client_t *item, *temp;

    list_for_each_entry_safe(item, temp, &client_list_head, list)
    {
        list_del(&item->list);
        client_item_free(item);
    }
}

void client_list_dump()
{
    int i = 0;
    int ret = 0;
    FILE *fp = NULL;
    char lan_name[10];
    lan_client_t *item, *temp;

    fp = fopen("/tmp/lan-scan.json", "w");
    if(!fp)
    {
        return;
    }

    fprintf(fp, "[");

    list_for_each_entry_safe(item, temp, &client_list_head, list)
    {
        if(item->status == 1)
        {
            memset(lan_name, 0x0, sizeof(lan_name));
            ret = lan_device_to_name(item->device, lan_name, sizeof(lan_name));
            if(ret < 0)
            {
                continue;
            }
                    
            fprintf(fp, "%s{\"mac\":\"%s\",\"ip\":\"%s\",\"host\":\"%s\",\"lan\":\"%s\"}", ((i > 0) ? "," : ""), 
                item->macaddr, item->ipaddr, ((item->hostname[0] == '\0') ? "unknown" : item->hostname), lan_name);
            i ++;
        }
    }
    fprintf(fp, "]");
    fclose(fp);
}

void dump_test()
{
    int i = 0;
    int ret = 0;    
    char lan_name[10];
    lan_client_t *item, *temp;

    printf("%-8s %-18s %-16s %-20s %-10s %-8s\n", 
        "index", "macaddr", "ipaddr", "hostname", "lan", "status");
    
    list_for_each_entry_safe(item, temp, &client_list_head, list)
    {
        memset(lan_name, 0x0, sizeof(lan_name));
        ret = lan_device_to_name(item->device, lan_name, sizeof(lan_name));
        if(ret < 0)
        {
            continue;
        }

        printf("%-8d %-18s %-16s %-20s %-10s %-1d\n", i, item->macaddr, 
            item->ipaddr, ((item->hostname[0] == '\0') ? "unknown" : item->hostname), lan_name, item->status);
        i ++;
    }
}

void get_hostname_by_dhcpd(lan_client_t *item)
{
    int ret = 0;

    ret = find_udhcpd_host_name(item->device, item->ipaddr, item->hostname, sizeof(item->hostname));
    if(ret < 0)
    {
        return;
    }
}

void parse_proc_arp()
{
    int ret = 0;
    FILE *fp = NULL;
    char ipaddr[16];
    char macaddr[18];
    char device[20];
    unsigned int flags = 0;
    char line[128] = {0};
    lan_client_t *item = NULL;
    int info_changed = 0;

    fp = fopen("/proc/net/arp", "r");
    if(!fp)
    {
        return;
    }

    reset_client_status();

    fgets(line, sizeof(line), fp);

    while(fgets(line, sizeof(line), fp))
    {
        ret = sscanf(line, "%s %*s 0x%8X %s %*s %s", ipaddr, &flags, macaddr, device);
        if(ret != 4)
        {
            continue;
        }
        
        if(flags == 0 || 
            strcmp(macaddr, "00:00:00:00:00:00") == 0)
        {
            continue;
        }
        
        if(get_lan_idx(device) < 0)
        {
            continue;
        }

        item = find_client_by_mac(macaddr);
        if(!item)
        {
            item = client_item_new();
            if(!item)
            {
                continue;
            }

            strncpy(item->ipaddr, ipaddr, sizeof(item->ipaddr) - 1);
            strncpy(item->macaddr, macaddr, sizeof(item->macaddr) - 1);
            strncpy(item->device, device, sizeof(item->device) - 1);
            item->uptime = time(NULL);
            item->status = 1;
            
            get_hostname_by_dhcpd(item);

            if(item->hostname[0] == '\0')
            {            
                nbt_query_send(g_nbt_sock, ipaddr);
            }

            list_add(&item->list, &client_list_head);
        }
        else
        {
            if(strcmp(item->ipaddr, ipaddr) != 0)
            {
                info_changed = 1;
                strncpy(item->ipaddr, ipaddr, sizeof(item->ipaddr) - 1);
            }
            
            if(strcmp(item->device, device) != 0)
            {
                info_changed = 1;
                strncpy(item->device, device, sizeof(item->device) - 1);  
            }

            if(info_changed)
            {
                item->uptime = time(NULL);
                item->status = 1;
            }
        }
    }

    fclose(fp);
}

#define NETBIOS_UTILS

void name_mangle(char *p)
{
    int i;

    p[0] = 32;
    p[1] = (('*' >> 4) & 0x0F) + 'A';
    p[2] = ('*' & 0x0F) + 'A';
    for (i = 3; i < 33; i++)
        p[i] = 'A';
    p[i] = '\0';
}

int nbt_sock_init()
{
    int ret = 0;
	int sockfd = -1;
	struct sockaddr_in addr;
	
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sockfd < 0)
    {   
        perror("socket: ");
		return -1;
    }
    
	memset(&addr, 0, sizeof(addr));
    
	addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    addr.sin_port = htons(0);
    
	ret = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if(ret < 0)
    {
        perror("bind: ");
        close(sockfd);
		return -1;
    }
    
    return sockfd;
}

int nbt_query_send(int sockfd, char *ipaddr)
{
    int ret = 0;
    ns_name_query req;
    static uint16_t xid = 0;
    
    struct sockaddr_in addr;

    bzero(&addr, sizeof(addr));
    addr.sin_family = PF_INET;
    addr.sin_port = htons(137);
    addr.sin_addr.s_addr = inet_addr(ipaddr);

    xid ++;

    memset(&req, 0x0, sizeof(ns_name_query));
    
	req.trans_id = htons(xid);
	req.flags = htons(0x0010);
	req.questions = htons(1);
	req.answers = 0;
	req.authority_RRs = 0;
	req.additional_RRs = 0;
    name_mangle((char *)req.name);
	req.query_type = htons(0x21);
	req.query_class = htons(0x01);

    ret = sendto(sockfd, (char *)&req, sizeof(ns_name_query), 0, 
        (struct sockaddr *)&addr, sizeof(addr));
    if(ret < 0)
    {
        perror("sendto:");
        return -1;
    }

    return 0;
}

static void get_nbtstat_name(lan_client_t *item, char *buff, int len)
{
	uint16_t num;
	uint8_t *p, *e;
    char *tmp;
    ns_nbtstat_resp_hdr *resp;

    /* get nbtstat name */
    if(len <= sizeof(ns_nbtstat_resp_hdr))
    {
        return;
    }
    
    resp = (ns_nbtstat_resp_hdr *)buff;
    
    num = resp->name_num;
    p = (uint8_t *)&buff[NS_HDR_LEN];
    e = p + (num * 18);
    for (; p < e; p += 18)
    {
        if (p[15] == 0 && (p[16] & 0x80) == 0)
        {
            break;
        }
        if (p == e)
        {
            return;
        }
    }

    tmp = trim_str((char *)p);
    strncpy(item->hostname, tmp, sizeof(item->hostname) - 1);
    
}

int nbt_reply_parse(int sockfd)
{
    int ret = 0;
    socklen_t addrlen;
    struct sockaddr_in addr;
    lan_client_t *item = NULL;
    char buff[512] = {0};
    char ipaddr[16] = {0};

    addrlen = sizeof(struct sockaddr_in);
    memset(&addr, 0x0, addrlen);
    ret = recvfrom(sockfd, buff, sizeof(buff), 0, (struct sockaddr *)&addr, &addrlen);
    if(ret < 0)
    {
        perror("recvfrom:");
        return -1;
    }

    strncpy(ipaddr, inet_ntoa(addr.sin_addr), sizeof(ipaddr) - 1);
    
    item = find_client_by_ip(ipaddr);
    if(!item)
    {
        printf("unknow error\n");
        return -1;
    }

    get_nbtstat_name(item, buff, ret);

    return 0;
}

#define ARP_UTILS

struct arp_sock *get_arp_sock(char *device)
{
    int i = 0;
    int lan_num = 0;

    get_lan_num(&lan_num);

    for(i = 0; i < lan_num; i ++)
    {        
        if(strcmp(lan_arps[i].device, device) == 0)
        {
            return &lan_arps[i];
        }
    }

    return NULL;
}

int lan_arp_sock_init()
{
    int i = 0;
    int ret = 0;
    int lan_num = 0;
    uint8_t local_ip[4];
    uint8_t local_mac[6];

    get_lan_num(&lan_num);

    for(i = 0; i < lan_num; i ++)
    {        
        lan_arps[i].sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if(lan_arps[i].sockfd < 0)
        {
            perror("socket");
            continue;
        }
        
        ret = get_device_ip_mac(lan_arps[i].device, local_ip, local_mac);
        if(ret < 0)
        {
            close(lan_arps[i].sockfd);
            lan_arps[i].sockfd = -1;
            continue;
        }

        memset(&lan_arps[i].eth_in, 0x0, sizeof(struct sockaddr_ll));
        memset(&lan_arps[i].arp, 0x0, sizeof(arp_packet_t));
        
        lan_arps[i].eth_in.sll_family = PF_PACKET;
        lan_arps[i].eth_in.sll_ifindex = if_nametoindex(lan_arps[i].device);

        memset(lan_arps[i].arp.h_dest, 0xFF, 6);
        memcpy(lan_arps[i].arp.h_source, local_mac, 6);
        lan_arps[i].arp.h_proto = htons(0x0806);
        
        lan_arps[i].arp.ar_hrd = htons(0x0001);
        lan_arps[i].arp.ar_pro = htons(ETH_P_IP);
        lan_arps[i].arp.ar_hln  = 6;
        lan_arps[i].arp.ar_pln = 4;
        lan_arps[i].arp.ar_op = htons(0x0001);
        
        memcpy(lan_arps[i].arp.ar_sha, local_mac, 6);
        memcpy(lan_arps[i].arp.ar_sip, local_ip, 4);
    }

    return 0;
}

int arp_mon_sock_init()
{
    int sockfd = -1;

    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sockfd < 0)
    {
        perror("socket");
        return -1;
    }

    return sockfd;
}

int arp_request_send(struct arp_sock *sock, char *macaddr, char *ipaddr)
{
    int ret = 0;
    unsigned int ip;

    if(sock->sockfd < 0)
    {
        return -1;
    }
    
    ip = inet_addr(ipaddr);

    memcpy(sock->arp.ar_tip, &ip, 4);
    ret = sendto(sock->sockfd, &sock->arp, sizeof(arp_packet_t), 0, (struct sockaddr *)(&sock->eth_in), sizeof(sock->eth_in));
    if(ret < 0)
    {
        printf("sendto failed!\n");
        return -1;
    }

    return 0;
}

int arp_reply_parse(int sockfd)
{   
    int ret = 0;
    arp_packet_t *arp;
    char buff[100] = {0};
    char ip[16] = {0};
    char mac[18] = {0};
    socklen_t len = 0;
    struct sockaddr_ll addr;
    lan_client_t *item;

    len = sizeof(struct sockaddr_ll);

    ret = recvfrom(sockfd, buff, sizeof(buff), 0, (struct sockaddr *)&addr, &len);
    if(ret < 0)
    {
        perror("recvfrom");
        return -1;
    }

    arp = (arp_packet_t *)buff;

    if(ntohs(arp->ar_op) == 2)
    {    
        snprintf(ip, sizeof(ip), "%u.%u.%u.%u", arp->ar_sip[0], arp->ar_sip[1], 
            arp->ar_sip[2], arp->ar_sip[3]);
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", arp->ar_sha[0],
            arp->ar_sha[1], arp->ar_sha[2], arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5]);

        item = find_client_by_mac(mac);
        if(item)
        {
            if(strcmp(ip, item->ipaddr) == 0)
            {
                item->status = 1;
            }
        }
    }    

    return 0;
}

/* 发送ARP请求，检查是否在线 */
void arp_clients_request()
{
    lan_client_t *item;
    struct arp_sock *sock;

    list_for_each_entry(item, &client_list_head, list)
    {
        item->status = 0;
        
        sock = get_arp_sock(item->device);
        if(!sock)
        {
            continue;
        }
        
        arp_request_send(sock, item->macaddr, item->ipaddr);
    }    
}

#define MAIN_ROUTINE

void sig_handle(int signo)
{
    switch(signo)
    {
        case SIGUSR1:
            g_sig_usr1 = 1;
            break;
        case SIGUSR2:
            g_sig_usr2 = 1;
            break;
        case SIGTERM:
        case SIGKILL:
            g_sig_exit = 1;
            break;
    }
}

void main_loop()
{
    int ret = 0;
    fd_set rfds;
    int maxfd = 0;
    struct timeval timeo;

    g_arp_sock = arp_mon_sock_init();
    if(g_arp_sock < 0)
    {
        printf("create arp mon sock failed!\n");
        goto err;
    }

    ret = lan_arp_sock_init();
    if(ret < 0)
    {        
        printf("create lan arp sock failed!\n");
        goto err;
    }

    g_nbt_sock = nbt_sock_init();
    if(g_nbt_sock < 0)
    {
        printf("nbt_sock_init failed!\n");
        goto err;
    }

    ev_timer_init(&g_arp_timer);
    ev_timer_init(&g_scan_timer);

    maxfd = MAX(maxfd, g_arp_sock);
    maxfd = MAX(maxfd, g_nbt_sock);
    maxfd = MAX(maxfd, g_arp_timer.fd);
    maxfd = MAX(maxfd, g_scan_timer.fd);

    /* 1s后开启扫描 */
    ev_timer_mod(&g_scan_timer, NULL, NULL, 1);

    while(1)
    {
        FD_ZERO(&rfds);
        FD_SET(g_arp_sock, &rfds);
        FD_SET(g_nbt_sock, &rfds);
        FD_SET(g_arp_timer.fd, &rfds);
        FD_SET(g_scan_timer.fd, &rfds);

        timeo.tv_sec = 1;
        timeo.tv_usec = 0;
    
        ret = select(maxfd + 1, &rfds, NULL, NULL, &timeo);
        if(ret <= 0)
        {
            if(ret == 0)
            {
                continue;
            }
                    
            if(errno != EINTR || g_sig_exit)
            {
                printf("select : %s\n", strerror(errno));
                exit(1);
            }

            if(g_sig_usr1)
            {   
                /* 发送arp请求，等待回复，超时输出结果 */
                arp_clients_request();
                ev_timer_mod(&g_arp_timer, NULL, NULL, 1);
                g_sig_usr1 = 0;
            }

            if(g_sig_usr2)
            {
                /* 调试用 */
                dump_test();
                g_sig_usr2 = 0;
            }

            continue;
        }

        /* arp response */
        if(FD_ISSET(g_arp_sock, &rfds))
        {
            ret = arp_reply_parse(g_arp_sock);
            if(ret < 0)
            {
                continue;
            }
        }

        /* nbns response */
        if(FD_ISSET(g_nbt_sock, &rfds))
        {
            ret = nbt_reply_parse(g_nbt_sock);
            if(ret < 0)
            {
                continue;
            }
        }

        /* arp timerfd */
        if(FD_ISSET(g_arp_timer.fd, &rfds))
        {
            client_list_dump();
            ev_timer_stop(&g_arp_timer);
        }

        /* arp scan timerfd */
        if(FD_ISSET(g_scan_timer.fd, &rfds))
        {
            parse_proc_arp();
            ev_timer_mod(&g_scan_timer, NULL, NULL, 5);
        }
    }   

err:
    ev_timer_destroy(&g_arp_timer);
    ev_timer_destroy(&g_scan_timer);

}

int main(int argc, char *argv[])
{
    pid_t pid;
    FILE *fp = NULL;
    int no_daemon = 0;

    signal(SIGUSR1, sig_handle);
    signal(SIGUSR2, sig_handle);
    signal(SIGTERM, sig_handle);
    signal(SIGKILL, sig_handle);

    if(argc >= 2)
    {
        if(strcmp(argv[1], "-f") == 0)
        {
            no_daemon = 1;
        }
    }

    if(!no_daemon)
    {
        if(daemon(0, 0) < 0)
        {
            perror("daemon");
            exit(1);
        }
    }
    
    /* 写入PID，用于其他进程获取 */
    pid = getpid();
    if((fp = fopen(PID_FILE, "w")) != NULL)
    {
        fprintf(fp, "%d", pid);
        fclose(fp);
    }

    INIT_LIST_HEAD(&client_list_head);

    main_loop();

    client_list_destroy();
    unlink(PID_FILE);

    return 0;
}
