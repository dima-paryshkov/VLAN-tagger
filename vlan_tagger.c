#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <features.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include "interface/interface.h"
#include "ip_pool/ip_pool.h"

#define ETHERNET_FRAME_SIZE 1522
#define DFLT_CONF_FILE ".pool_ip_vlan.conf"
#define LOGFILE_NAME "vlan_tagger.log"
const int LEN_IF_NAME = 15;
int is_daemon_running = 1;

char *in_if = NULL;
char *out_if = NULL;
char *name_conf_file = NULL;

static int argv_process(
    int argc,
    char **argv);

static int create_daemon(void);

static void exit_signal_handler(int signum);

int tagger(
    unsigned char *buffer,
    size_t size_buffer);

static int handle_interface_shutdown(
    char *in_if,
    char *out_if,
    FILE *log_file);

int main(int argc, char **argv)
{
    struct ifreq interface_in = {0};
    struct ifreq interface_out = {0};
    int socket_in_raw = 0;
    int socket_out_raw = 0;
    struct sockaddr_ll socket_in_raw_address = {0};
    struct sockaddr_ll socket_out_raw_address = {0};
    unsigned char *frame_buffer = NULL;
    struct iphdr *iph = {0};
    struct in_addr ip = {0};
    int socket_raw_adress_size = sizeof(struct sockaddr_ll);
    int frame_size = 0;

    int return_code = 0;
    FILE *log_file = NULL;

    if (argc < 2)
    {
        fprintf(stderr, "Too few arguments. Use %s -h for detail\n", argv[0]);
        return -1;
    }

    pool_ip_vlan = malloc(max_size_pool * sizeof(struct ip_vlan_t));
    if (pool_ip_vlan == NULL)
    {
        perror("malloc");
        return -1;
    }

    if (argv_process(argc, argv) == 1)
    {
        return 0;
    }

    return_code = is_interface_exist(in_if);
    if (return_code == -1)
    {
        fprintf(stderr, "Can't get info about %s\n", in_if);
        return -1;
    }
    else if (return_code == 1)
    {
        fprintf(stderr, "Input interface %s doesn't exist\n", in_if);
        return -1;
    }

    return_code = is_interface_exist(out_if);
    if (return_code == -1)
    {
        fprintf(stderr, "Can't get info about %s\n", out_if);
        return -1;
    }
    else if (return_code == 1)
    {
        fprintf(stderr, "Output interface %s doesn't exist\n", out_if);
        return -1;
    }

    // return_code = create_daemon();
    // if (return_code == 0)
    // {
    //     return 0;
    // }
    // else if (return_code == -1)
    // {
    //     fprintf(stderr, "Can't create daemon\n");
    //     return -1;
    // }

    if ((log_file = fopen(LOGFILE_NAME, "w")) == NULL)
    {
        perror("fopen(logfile)");
        return -1;
    }
    socket_in_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_in_raw < 0)
    {
        fprintf(log_file, "Creating raw socket failure. Try running as superuser: %s\n", strerror(errno));
        fclose(log_file);
        return -1;
    }

    socket_in_raw_address.sll_family = AF_PACKET;
    socket_in_raw_address.sll_protocol = htons(ETH_P_ALL);
    socket_in_raw_address.sll_ifindex = if_nametoindex(in_if);
    if (bind(socket_in_raw, (struct sockaddr *)&socket_in_raw_address, socket_raw_adress_size) < 0)
    {
        perror("bind failed\n");
        fprintf(log_file, "Bind socket to interface: %s\n", strerror(errno));
        fclose(log_file);
        return -1;
    }

    socket_out_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_out_raw < 0)
    {
        fprintf(log_file, "Creating raw socket failure. Try running as superuser: %s\n", strerror(errno));
        fclose(log_file);
        return -1;
    }

    socket_out_raw_address.sll_family = AF_PACKET;
    socket_out_raw_address.sll_protocol = htons(ETH_P_ALL);
    socket_out_raw_address.sll_ifindex = if_nametoindex(out_if);
    if (bind(socket_out_raw, (struct sockaddr *)&socket_out_raw_address, socket_raw_adress_size) < 0)
    {
        fprintf(log_file, "Bind socket to interface: %s\n", strerror(errno));
        fclose(log_file);
        return -1;
    }

    frame_buffer = malloc(ETHERNET_FRAME_SIZE);

    while (is_daemon_running)
    {
        frame_size = recvfrom(socket_in_raw, frame_buffer, ETHERNET_FRAME_SIZE, 0,
                              (struct sockaddr *)&socket_in_raw_address, &socket_raw_adress_size);
        if (frame_size < 0)
        {
            fprintf(log_file, "Failure accepting frame from %s\n", out_if);
            handle_interface_shutdown(in_if, out_if, log_file);
        }

        if (tagger(frame_buffer, frame_size) == -1)
        {
            iph = (struct iphdr *)(frame_buffer + sizeof(struct ethhdr));
            ip.s_addr = iph->saddr;
            fprintf(log_file, "ip %s\n", inet_ntoa(ip));
        }

        iph = (struct iphdr *)(frame_buffer + sizeof(struct ethhdr));
        ip.s_addr = iph->saddr;
        fprintf(stdout, "ip %s\n", inet_ntoa(ip));

        frame_size = sendto(socket_out_raw, frame_buffer, frame_size + 4, 0,
                            (struct sockaddr *)&socket_out_raw_address, socket_raw_adress_size);
        if (frame_size < 0)
        {
            fprintf(log_file, "Failure send frame to %s\n", out_if);
            handle_interface_shutdown(in_if, out_if, log_file);
        }
    }
    fclose(log_file);
    return 0;
}

static int argv_process(
    int argc,
    char **argv)
{
    struct ip_vlan_t ip_vlan_entry = {0};
    FILE *conf_file = NULL;
    char ip_str[15] = {0};

    int i = 1;
    while (i < argc)
    {
        switch (argv[i][1])
        {
        case 'f':
        {
            name_conf_file = argv[i + 1];
            i = argc;

            conf_file = fopen(name_conf_file, "r");
            if (conf_file == NULL)
            {
                fprintf(stderr, "Can't open file %s: %s\n", name_conf_file, strerror(errno));
                return -12;
            }

            in_if = malloc(LEN_IF_NAME);
            out_if = malloc(LEN_IF_NAME);
            if (in_if == NULL || out_if == NULL)
            {
                perror("malloc_if");
                return -11;
            }

            fscanf(conf_file, "%s %s", in_if, out_if);

            while (fscanf(conf_file, "%s %hd", ip_str, &ip_vlan_entry.vlan) != EOF)
            {
                if (inet_aton(ip_str, &ip_vlan_entry.ip_addr) == 0)
                {
                    fprintf(stderr, "Incorrect ip addres %s \n", ip_str);
                    break;
                }
                add_ip_to_pool(&ip_vlan_entry);
            }

            fclose(conf_file);
            break;
        }
        case 'i':
        {
            in_if = argv[i + 1];
            i += 2;
            break;
        }
        case 'o':
        {
            out_if = argv[i + 1];
            i += 2;
            break;
        }
        case 'p':
        {
            i += 1;
            while (i < argc && argv[i][1] != 'i' && argv[i][1] != 'o')
            {
                if (argv[i][1] == 'f' && argv[i][1] == 'h')
                {
                    fprintf(stderr, "Incorrect options\n");
                    fprintf(stderr, "Use '%s -h' for details\n", argv[0]);
                    return -10;
                }

                ip_vlan_entry.vlan = atoi(argv[i + 1]);
                inet_aton(argv[i], &ip_vlan_entry.ip_addr);
                add_ip_to_pool(&ip_vlan_entry);
                i += 2;
            }
            print_pool_to_file(DFLT_CONF_FILE, pool_ip_vlan, size_pool, in_if, out_if);
            break;
        }
        case 'h':
        {
            printf("\n\t--- VLAN-tagger info ---\n\n");
            printf("\t-i is input interface\n");
            printf("\t-o is output interface\n");
            printf("\t-p is list of pool ip_vlan\n");
            printf("\t-f is file with pool\n");
            printf("\tAttention! You can't use 'iop' options with 'f' option\n\n");
            printf("\tUse %s -i <input if> -o <output if> -p <list of pool ip>, \n \
                when pool ip – list <ip> <№ VLAN>\n \tOR \n",
                   argv[0]);

            printf("\tUse %s -f <name of config file>\n\n", argv[0]);

            return 1;
        }
        case '?':
        {
            printf("Uncorrect option(s)! Use '%s -h' to get info.\n", argv[0]);
            return 1;
        }
        }
    }

    pool_ip_vlan = realloc(pool_ip_vlan, size_pool * sizeof(struct ip_vlan_t));

    if (in_if == NULL || out_if == NULL || size_pool == 0)
    {
        fprintf(stderr, "Too few arguments or incorrect value of arguments. Use '%s -h' for detail\n", argv[0]);
        return 1;
    }

    return 0;
}

int tagger(
    unsigned char *buffer,
    size_t size_buffer)
{
    struct iphdr *iph = {0};
    struct in_addr send_ip_addr = {0};
    struct vlanhdr vlanhdr = {0};
    unsigned char *pt = NULL;
    int i = 0;
    int vlan = 0;

    iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    send_ip_addr.s_addr = iph->saddr;

    vlan = find_vlan_by_ip(send_ip_addr);
    if (vlan == -1)
    {
        return -1;
    }

    for (i = size_buffer - 1; i >= 16; i--)
    {
        buffer[i] = buffer[i - 4];
    }

    /* Для 802.1Q используется значение 0x8100 в качестве tpid*/
    vlanhdr.tpid = 0x8100;
    vlanhdr.tci = vlan;
    vlanhdr.tci &= 0x1F;

    memcpy(buffer + ETH_ALEN * 2, &vlanhdr, sizeof(struct vlanhdr));

    return 0;
}

static void exit_signal_handler(int signum)
{
    is_daemon_running = 0;
}

static int create_daemon(void)
{
    pid_t pid = 0;
    pid_t sid = 0;

    pid = fork();

    if (pid == -1)
    {
        perror("fork");
        return -1;
    }
    else if (pid > 0)
    {
        return 0;
    }

    sid = setsid();
    if (sid == -1)
    {
        perror("setsid");
        return -1;
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, exit_signal_handler);

    pid = fork();

    if (pid == -1)
    {
        perror("fork");
        return -1;
    }
    else if (pid > 0)
    {
        return 0;
    }

    umask(0);

    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--)
    {
        close(x);
    }

    return 1;
}

static int handle_interface_shutdown(
    char *in_if,
    char *out_if,
    FILE *log_file)
{
    if (is_interface_online(in_if) != 1)
    {
        fprintf(log_file, "input if(%s) shutdown\n", in_if);
        while (is_interface_online(in_if) != 1)
        {
            sleep(1);
        }
        fprintf(log_file, "input if(%s) is working\n", in_if);
    }

    if (is_interface_online(out_if) != 1)
    {
        fprintf(log_file, "output if(%s) shutdown\n", out_if);
        while (is_interface_online(out_if) != 1)
        {
            sleep(1);
        }
        fprintf(log_file, "output if(%s) is working", out_if);
    }

    /*
        The function will end only when both interfaces are available.
    */
    if (is_interface_online(in_if) != 1 && is_interface_online(out_if) != 1)
    {
        handle_interface_shutdown(in_if, out_if, log_file);
    }
    return 0;
}
