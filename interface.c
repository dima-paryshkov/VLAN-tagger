#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include "interface.h"

int is_interface_online(char* interface) 
{
    struct ifreq ifr = {0};
    int sock = socket(PF_INET6, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, interface);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) 
    {
        perror("SIOCGIFFLAGS");
        close(sock);
        return -1;
    }

    close(sock);
    return !!(ifr.ifr_flags & IFF_RUNNING);
}

int is_interface_exist(const char *ifname)
{
    struct ifaddrs *ifaddr = {0};
    struct ifaddrs *ifa = {0};

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_PACKET)
            continue;
        
        if (strcmp(ifa->ifa_name, ifname) == 0) 
        {
            return 0;
        }
    }

    freeifaddrs(ifaddr);
    return 1;
}