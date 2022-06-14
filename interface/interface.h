int is_interface_online(char* interface); 

int is_interface_exist(const char *ifname);

void check_interface(char *_if);

int handle_interface_shutdown(
    char *in_if, 
    char *out_if);