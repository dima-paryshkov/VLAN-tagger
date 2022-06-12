#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "ip_pool.h"

struct ip_vlan_t *pool_ip_vlan = NULL;

size_t size_pool = 0;
size_t max_size_pool = 50;

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

int find_vlan_by_ip(struct in_addr ip_addr)
{
    for (int i = 0; i < size_pool; i++)
    {
        if (ip_addr.s_addr == pool_ip_vlan[i].ip_addr.s_addr)
        {
            return pool_ip_vlan[i].vlan;
        }
    }
    return -1;
}

void print_pool_to_file(
    char *filename,
    struct ip_vlan_t *pool_addrs,
    size_t size_pool,
    char* in_if,
    char* out_if)
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