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

void swap(
    struct ip_vlan_t *a,
    struct ip_vlan_t *b)
{
    struct ip_vlan_t t = *a;
    *a = *b;
    *b = t;
}

int partition(
    struct ip_vlan_t *pool_ip_vlan,
    int low,
    int high)
{
    struct ip_vlan_t pivot = pool_ip_vlan[high];

    int i = (low - 1);

    for (int j = low; j < high; j++)
    {
        if (pool_ip_vlan[j].ip_addr.s_addr <= pivot.ip_addr.s_addr)
        {
            i++;
            swap(pool_ip_vlan + i, pool_ip_vlan + j);
        }
    }

    swap(pool_ip_vlan + i + 1, pool_ip_vlan + high);

    return (i + 1);
}

void sort_quick(
    struct ip_vlan_t *pool_ip_vlan,
    int low,
    int high)
{
    if (low < high)
    {
        int pi = partition(pool_ip_vlan, low, high);
        sort_quick(pool_ip_vlan, low, pi - 1);
        sort_quick(pool_ip_vlan, pi + 1, high);
    }
}

int find_vlan_by_ip(struct in_addr ip_addr)
{
    int low = 0;
    int high = size_pool - 1;
    int middle = 0;

    while (low <= high)
    {
        middle = (low + high) / 2;
        if (ip_addr.s_addr < pool_ip_vlan[middle].ip_addr.s_addr)
        {
            high = middle - 1;
        }
        else if (ip_addr.s_addr > pool_ip_vlan[middle].ip_addr.s_addr)
        {
            low = middle + 1;
        }
        else
        {
            return pool_ip_vlan[middle].vlan;
        }
    }
    return -1;
}

void print_pool_to_file(
    char *filename,
    struct ip_vlan_t *pool_addrs,
    size_t size_pool,
    char *in_if,
    char *out_if)
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