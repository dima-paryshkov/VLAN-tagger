#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <features.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>

#define ETR_FRAME_SIZE 1496
#define ETR_FRAME_WITH_VLAN_SIZE 1500

const int LEN_IF_NAME = 15;

struct ip_vlan_t
{
    unsigned short int vlan;
    struct in_addr ip_addr;
};

struct vlanhdr
{
    uint16_t tpid;
    uint16_t tci;
};

char *in_if_name = NULL;
char *out_if_name = NULL;
char *name_conf_file = NULL;
int count_send_frames = 5;

struct ip_vlan_t *pool_ip_vlan = NULL;

size_t size_pool = 0;
size_t max_size_pool = 50;

int create_frame(
    unsigned char *frame_buffer,
    unsigned char *frame_buffer_with_vlan);

static int argv_process(
    int argc,
    char **argv);

int add_ip_to_pool(struct ip_vlan_t *ip_vlan_entry);

int create_frame(unsigned char *frame_buffer, unsigned char *frame_buffer_with_vlan);

int main(int argc, char **argv)
{
    struct ifreq in_if = {0};
    struct ifreq out_if = {0};
    int socket_in_if = 0;
    int socket_out_if = 0;
    struct sockaddr_ll socket_in_address = {0};
    struct sockaddr_ll socket_out_address = {0};
    unsigned int socket_adress_size = sizeof(struct sockaddr_ll);
    unsigned char *frame_buffer = NULL;
    unsigned char *frame_buffer_with_vlan = NULL;
    unsigned char *frame_recv_buffer = NULL;
    int frame_size = 0;
    int count_succes_frame = 0;
    int return_code = 0;

    if (argc != 5)
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

    return_code = argv_process(argc, argv);
    if (return_code == 1)
    {
        return 0;
    }
    else if (return_code == -1)
    {
        return -1;
    }

    socket_in_if = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_in_if < 0)
    {
        perror("Creating raw socket failure. Try running as superuser");
        return -1;
    }

    socket_in_address.sll_family = AF_PACKET;
    socket_in_address.sll_protocol = htons(ETH_P_ALL);
    socket_in_address.sll_ifindex = if_nametoindex(in_if_name);
    if (bind(socket_in_if, (struct sockaddr *)&socket_in_address, socket_adress_size) < 0)
    {
        perror("bind failed\n");
        close(socket_in_if);
        return -1;
    }

    socket_out_if = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_out_if < 0)
    {
        perror("Creating raw socket failure. Try running as superuser");
        return -1;
    }

    socket_out_address.sll_family = AF_PACKET;
    socket_out_address.sll_protocol = htons(ETH_P_ALL);
    socket_out_address.sll_ifindex = if_nametoindex(out_if_name);
    if (bind(socket_out_if, (struct sockaddr *)&socket_out_address, socket_adress_size) < 0)
    {
        perror("bind failed\n");
        close(socket_in_if);
        close(socket_out_if);
        return -1;
    }

    frame_buffer = malloc(ETR_FRAME_SIZE);
    frame_buffer_with_vlan = malloc(ETR_FRAME_WITH_VLAN_SIZE);
    frame_recv_buffer = malloc(ETR_FRAME_WITH_VLAN_SIZE);

    for (int i = 0; i < count_send_frames; i++)
    {
        create_frame(frame_buffer, frame_buffer_with_vlan);

        frame_size = write(socket_in_if, frame_buffer, ETR_FRAME_SIZE);
        if (frame_size != ETR_FRAME_SIZE || frame_size < 0)
        {
            perror("sendto");
        }
        else
        {
            while ((frame_size = recvfrom(socket_out_if, frame_recv_buffer,
                                          ETR_FRAME_WITH_VLAN_SIZE, 0, (struct sockaddr *)&socket_out_address,
                                          &socket_adress_size)) != ETR_FRAME_WITH_VLAN_SIZE)
                ;

            if (strcmp(out_if_name, "lo") == 0)
            {
                while ((frame_size = recvfrom(socket_out_if, frame_recv_buffer,
                                              ETR_FRAME_WITH_VLAN_SIZE, 0, (struct sockaddr *)&socket_out_address,
                                              &socket_adress_size)) != ETR_FRAME_WITH_VLAN_SIZE)
                    ;
            }

            if (frame_size < 0)
            {
                perror("recvfrom");
            }
            else if (memcmp(frame_recv_buffer, frame_buffer_with_vlan,
                            ETR_FRAME_WITH_VLAN_SIZE) == 0)
            {
                count_succes_frame++;
            }
        }
    }

    printf("Test started using %s and %s interface\n", in_if_name, out_if_name);

    if (count_succes_frame == count_send_frames)
    {
        printf(" ----------------------------\n");
        printf(" %d tests passed successfully\n", count_succes_frame);
        printf(" ----------------------------\n");
    }
    else
    {
        printf("-------------------------\n");
        printf("Tests failed\n");
        printf("successfully %d, failed %d tests\n", count_succes_frame,
               count_send_frames - count_succes_frame);

        printf("-------------------------\n");
    }

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
            i += 2;

            conf_file = fopen(name_conf_file, "r");
            if (conf_file == NULL)
            {
                fprintf(stderr, "Can't open file %s: %s\n", name_conf_file, strerror(errno));
                return -1;
            }

            in_if_name = malloc(LEN_IF_NAME);
            out_if_name = malloc(LEN_IF_NAME);
            if (in_if_name == NULL || out_if_name == NULL)
            {
                perror("malloc_if");
                return -1;
            }

            fscanf(conf_file, "%s %s", in_if_name, out_if_name);
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
        case 'c':
        {
            count_send_frames = atoi(argv[i + 1]);
            i += 2;
            break;
        }
        case 'h':
        {
            printf("\n\t--- VLAN-tagger info ---\n\n");
            printf("\t-f is file with pool\n");
            printf("\t-c is count send frames\n");
            printf("\tAttention! You can't use 'iop' options with 'f' option\n\n");
            printf("\tUse %s -f <name of config file> -c <number of send frames>\n\n", argv[0]);

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

    if (in_if_name == NULL || out_if_name == NULL || size_pool == 0)
    {
        fprintf(stderr, "Too few arguments or incorrect value of arguments. Use '%s -h' for detail\n", argv[0]);
        return 1;
    }
    return 0;
}

int create_frame(unsigned char *frame_buffer, unsigned char *frame_buffer_with_vlan)
{
    struct ether_header *ethhdr = {0};
    struct iphdr *iphdr = {0};
    struct vlanhdr vlanhdr = {0};
    int num_ip_vlan = 0;
    short unsigned int hton_ip = 0;

    ethhdr = (struct ether_header *)frame_buffer;
    iphdr = (struct iphdr *)(frame_buffer + sizeof(struct ether_header));

    for (int i = 14; i < ETR_FRAME_SIZE; i++)
    {
        frame_buffer[i] = 0xFE;
        frame_buffer_with_vlan[i] = 0xFE;
    }

    for (int i = ETR_FRAME_SIZE; i < ETR_FRAME_WITH_VLAN_SIZE; i++)
    {
        frame_buffer_with_vlan[i] = 0xFE;
    }

    for (int i = 0; i < 6; i++)
    {
        ethhdr->ether_shost[i] = i;
    }
    for (int i = 0; i < 6; i++)
    {
        ethhdr->ether_dhost[i] = i;
    }

    ethhdr->ether_type = htons(ETH_P_IP);

    memcpy(frame_buffer_with_vlan, frame_buffer, 12);

    num_ip_vlan = rand() % size_pool - 1;
    iphdr->saddr = pool_ip_vlan[num_ip_vlan].ip_addr.s_addr;

    vlanhdr.tpid = ETH_P_8021Q;
    vlanhdr.tci = pool_ip_vlan[num_ip_vlan].vlan;
    vlanhdr.tci &= 0x1F;

    memcpy(frame_buffer_with_vlan + 12, &vlanhdr, sizeof(struct vlanhdr));
    hton_ip = htons(ETH_P_IP);
    memcpy(frame_buffer_with_vlan + 12 + sizeof(struct vlanhdr), &hton_ip, 2);

    iphdr = (struct iphdr *)(frame_buffer_with_vlan + sizeof(struct ether_header) + sizeof(struct vlanhdr));
    iphdr->saddr = pool_ip_vlan[num_ip_vlan].ip_addr.s_addr;
    return 0;
}

int is_collision(struct ip_vlan_t *ip_vlan_entry)
{
    for (int i = 0; i < size_pool; i++)
    {
        if (pool_ip_vlan[i].ip_addr.s_addr == ip_vlan_entry->ip_addr.s_addr)
        {
            if (pool_ip_vlan[i].vlan == ip_vlan_entry->vlan)
            {
                fprintf(stderr, "Warning: duplicate entry ip_addr %s vlan %d\n",
                        inet_ntoa(ip_vlan_entry->ip_addr), ip_vlan_entry->vlan);
                return 1;
            }
            else
            {
                fprintf(stderr, "Error: find collision entries\n");
                fprintf(stderr, "\t|- ip_addr %s vlan %d\n",
                        inet_ntoa(ip_vlan_entry->ip_addr), ip_vlan_entry->vlan);

                fprintf(stderr, "\t|- ip_addr %s vlan %d\n",
                        inet_ntoa(ip_vlan_entry->ip_addr), ip_vlan_entry->vlan);

                return -1;
            }
        }
    }

    return 0;
}

int add_ip_to_pool(struct ip_vlan_t *ip_vlan_entry)
{
    if (is_collision(ip_vlan_entry) == 0)
    {
        if (size_pool == max_size_pool)
        {
            max_size_pool += 50;
            pool_ip_vlan = realloc(pool_ip_vlan, max_size_pool * sizeof(struct ip_vlan_t));
            if (pool_ip_vlan == NULL)
            {
                perror("realloc");
                return -11;
            }
        }
        pool_ip_vlan[size_pool] = *ip_vlan_entry;
        size_pool++;
    }
    return 0;
}
