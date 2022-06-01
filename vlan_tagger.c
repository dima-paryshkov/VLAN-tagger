#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "interface.h"

#define DFLT_CONF_FILE ".pool_ip_vlan.conf"
const int LEN_IF_NAME = 15;

struct ip_vlan_t
{
    unsigned short int vlan;
    struct in_addr ip_addr;
};

struct ip_vlan_t *pool_ip_vlan = NULL;
size_t size_pool = 0;
size_t max_size_pool = 50;

char *in_if = NULL;
char *out_if = NULL;
char *name_conf_file = NULL;

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

void print_pool_to_file(char *filename, struct ip_vlan_t *pool_addrs, size_t size_pool)
{
    FILE *pool_conffile = NULL;

    if ((pool_conffile = fopen(filename, "w")) == NULL)
    {
        perror("fopen");
    }

    fprintf(pool_conffile, "%s %s\n", in_if, out_if);

    for (int i = 0; i < size_pool; i++)
    {
        fprintf(pool_conffile, "%s %d\n", inet_ntoa(pool_addrs[i].ip_addr), pool_addrs[i].vlan);
    }
    fclose(pool_conffile);
}

int argv_process(int argc, char **argv)
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
            print_pool_to_file(DFLT_CONF_FILE, pool_ip_vlan, size_pool);
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

int main(int argc, char **argv)
{
    int return_code = 0;

    if (argc < 2)
    {
        fprintf(stderr, "Too few arguments. Use %s -h for detail\n", argv[0]);
        return -1;
    }

    pool_ip_vlan = malloc(max_size_pool * sizeof(struct ip_vlan_t));
    if (pool_ip_vlan == NULL)
    {
        perror("malloc");
        return -11;
    }

    if (argv_process(argc, argv) == 1)
    {
        return 0;
    }

    return_code = is_interface_exist(in_if);
    if (return_code == -1)
    {
        fprintf(stderr, "Can't get info about %s\n", in_if);
        return -2;
    }
    else if (return_code == 1)
    {
        fprintf(stderr, "Input interface %s doesn't exist\n", in_if);
        return -3;
    }

    return_code = is_interface_exist(out_if);
    if (return_code == -1)
    {
        fprintf(stderr, "Can't get info about %s\n", out_if);
        return -2;
    }
    else if (return_code == 1)
    {
        fprintf(stderr, "Output interface %s doesn't exist\n", out_if);
        return -3;
    }

    return 0;
}
