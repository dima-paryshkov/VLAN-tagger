#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <syslog.h>
#include <stdlib.h>

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

void check_interface(char *_if)
{
    int return_code = 0;
    return_code = is_interface_exist(_if);
    if (return_code == -1)
    {
        fprintf(stderr, "Can't get info about %s\n", _if);
        exit(-1);
    }
    else if (return_code == 1)
    {
        fprintf(stderr, "Input interface %s doesn't exist\n", _if);
        exit(-1);
    }
}

int handle_interface_shutdown(
    char *in_if,
    char *out_if)
{
    if (is_interface_online(in_if) != 1)
    {
        syslog(LOG_WARNING, "input if(%s) shutdown\n", in_if);
        while (is_interface_online(in_if) != 1)
        {
            sleep(1);
        }
        syslog(LOG_WARNING, "input if(%s) is working\n", in_if);
    }

    if (is_interface_online(out_if) != 1)
    {
        syslog(LOG_WARNING, "output if(%s) shutdown\n", out_if);
        while (is_interface_online(out_if) != 1)
        {
            sleep(1);
        }
        syslog(LOG_WARNING, "output if(%s) is working", out_if);
    }

    /*
        The function will end only when both interfaces are available.
    */
    if (is_interface_online(in_if) != 1 && is_interface_online(out_if) != 1)
    {
        handle_interface_shutdown(in_if, out_if);
    }
    return 0;
}
