#ifndef LWIP_MPTCP_DEBUG
#define LWIP_MPTCP_DEBUG

struct mp_capable;
struct mp_join;
struct mp_dss;
struct mp_add_addr;
struct mp_remove_addr;
struct mp_fclose;
struct mp_server_addr;

#define LIST_MP_CAPABLE(x) list_mp_capable(x)
#define LIST_MP_JOIN(x) list_mp_join(x)
#define LIST_MP_DSS(x) list_mp_dss(x)
#define LIST_MP_ADD_ADDR(x) list_mp_add(x)
#define LIST_MP_REMOVE_ADDR(x) list_mp_remove(x)
#define LIST_MP_FCLOSE(x) list_mp_fclose(x)
#define LIST_MP_SERVER_ADDR(x) list_mp_server_addr(x)

#define LIST_STATE(x) list_state(x)
#define LIST_RCV_OPT(x) list_kind(x)

void list_state(int state);
void list_kind(int kind);

void list_mp_capable(const struct mp_capable* mp);
void list_mp_join(const struct mp_join* mp);
void list_mp_dss(const struct mp_dss* mp);
void list_mp_add(const struct mp_add_addr* mp);
void list_mp_remove(const struct mp_remove_addr* mp);
void list_mp_fclose(const struct mp_fclose* mp);
void list_mp_server_addr(const struct mp_server_addr* mp);
#endif
