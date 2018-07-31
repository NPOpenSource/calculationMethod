#ifndef LINUX_STUB_H
#define LINUX_STUB_H

#ifdef __cplusplus
extern "C" {
#endif

void setup_breakpad(void);
void add_datalink_route(int isWiFi,const char *env_item_name, char *host_ip, char *gateway, char *dev_name);
void add_datalink_dynamic_route(int isWiFi,char *host_ip);
void setThreadName(const char* name);



#ifdef __cplusplus
}
#endif
#endif //LINUX_STUB_H
