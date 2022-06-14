#include <stddef.h>

struct ip_vlan_t *pool_ip_vlan;
size_t size_pool;
size_t max_size_pool;

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
int is_collision(struct ip_vlan_t *ip_vlan_entry);

void print_pool_to_file(
    char *filename,
    struct ip_vlan_t *pool_addrs,
    size_t size_pool,
    char* in_if,
    char* out_if);

int add_ip_to_pool(struct ip_vlan_t *ip_vlan_entry);

void sort_quick(struct ip_vlan_t *pool_ip_vlan, int first, int last);

int find_vlan_by_ip(struct in_addr ip_addr);