#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <netinet/in.h>

#define ETR_FRAME_SIZE 1500
#define ETR_FRAME_WITH_VLAN_SIZE 1504

struct vlanhdr
{
    uint16_t tpid;
    uint16_t tci;
};

char list_ip[5][16] = {"140.106.157.116", "111.218.39.46", "59.108.145.157", \
    "142.15.121.152", "6.162.212.148"};

int list_vlan[5] = {3, 5, 4, 6, 5};

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
        frame_buffer[i] = 0xFF;
        frame_buffer_with_vlan[i] = 0xFF;
    }

    for (int i = ETR_FRAME_SIZE; i < ETR_FRAME_WITH_VLAN_SIZE; i++)
    {
        frame_buffer_with_vlan[i] = 0xFF;
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

    num_ip_vlan = rand() % 5;
    inet_aton(list_ip[num_ip_vlan], (struct in_addr *)&iphdr->saddr);

    memcpy(frame_buffer_with_vlan, frame_buffer, 12);

    vlanhdr.tpid = ETH_P_8021Q;
    vlanhdr.tci = list_vlan[num_ip_vlan];
    vlanhdr.tci &= 0x1F;

    memcpy(frame_buffer_with_vlan + 12, &vlanhdr, sizeof(struct vlanhdr));
    hton_ip = htons(ETH_P_IP);
    memcpy(frame_buffer_with_vlan + sizeof(struct vlanhdr), &hton_ip, 2);

    iphdr = (struct iphdr *)(frame_buffer_with_vlan + sizeof(struct ether_header) + sizeof(struct vlanhdr));
    inet_aton(list_ip[num_ip_vlan], (struct in_addr *)&iphdr->saddr);

    return 0;
}

int main(int argc, char **argv)
{
    const int COUNT_SEND_FRAME = 5;
    char *in_if_name = NULL;
    char *out_if_name = NULL;
    struct ifreq in_if = {0};
    struct ifreq out_if = {0};
    int socket_in_if = 0;
    int socket_out_if = 0;
    struct sockaddr socket_in_address = {0};
    struct sockaddr socket_out_address = {0};
    unsigned int socket_in_adress_size = 0;
    unsigned int socket_out_adress_size = 0;
    unsigned char *frame_buffer = NULL;
    unsigned char *frame_buffer_with_vlan = NULL;
    unsigned char *frame_recv_buffer = NULL;
    int frame_size = 0;
    int count_succes_frame = 0;

    if (argc != 3)
    {
        printf("Please specify inerface name\n");
        return -1;
    }

    in_if_name = argv[1];
    out_if_name = argv[2];

    socket_in_if = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_in_if < 0)
    {
        perror("Creating raw socket failure. Try running as superuser");
        return -2;
    }

    snprintf(in_if.ifr_name, sizeof(in_if.ifr_name), "%s", in_if_name);

    socket_in_adress_size = sizeof(socket_in_address);
    if (setsockopt(socket_in_if, SOL_SOCKET, SO_BINDTODEVICE, (void *)&in_if,
                   sizeof(in_if)) < 0)
    {
        perror("Failure binding socket to interface");
        return -3;
    }

    socket_out_if = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_out_if < 0)
    {
        perror("Creating raw socket failure. Try running as superuser");
        return -2;
    }

    snprintf(out_if.ifr_name, sizeof(out_if.ifr_name), "%s", out_if_name);

    socket_out_adress_size = sizeof(socket_out_address);
    if (setsockopt(socket_out_if, SOL_SOCKET, SO_BINDTODEVICE, (void *)&out_if,
                   sizeof(out_if)) < 0)
    {
        perror("Failure binding socket to interface");
        return -3;
    }

    frame_buffer = malloc(ETR_FRAME_SIZE);
    frame_buffer_with_vlan = malloc(ETR_FRAME_WITH_VLAN_SIZE);
    frame_recv_buffer = malloc(ETR_FRAME_WITH_VLAN_SIZE);

    frame_size = recvfrom(socket_in_if, frame_recv_buffer, ETR_FRAME_SIZE, 0,
        &socket_in_address, &socket_in_adress_size);

    for (int i = 0; i < COUNT_SEND_FRAME; i++)
    {
        create_frame(frame_buffer, frame_buffer_with_vlan);

        frame_size = sendto(socket_in_if, frame_buffer, ETR_FRAME_SIZE, 0,
            &socket_in_address, socket_in_adress_size);
        if (frame_size != ETR_FRAME_SIZE || frame_size < 0)
        {
            perror("sendto");
        }
        else
        {
            while ((frame_size = recvfrom(socket_out_if, frame_recv_buffer, 
                ETR_FRAME_WITH_VLAN_SIZE, 0, &socket_out_address, 
                &socket_out_adress_size)) != ETR_FRAME_WITH_VLAN_SIZE);

            if ( frame_size < 0)
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

    printf("Test started using %s and %s if\n", in_if_name, out_if_name);

    if (count_succes_frame == COUNT_SEND_FRAME)
    {
        printf("-------------------------\n");
        printf("Tests passed successfully\n");
        printf("-------------------------\n");
    }
    else
    {
        printf("-------------------------\n");
        printf("Tests failed\n");
        printf("successfully %d, failed %d tests\n", count_succes_frame, 
            COUNT_SEND_FRAME - count_succes_frame);
            
        printf("-------------------------\n");
    }

    return 0;
}