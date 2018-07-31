#ifndef MPTCP_UNALINGED
#define MPTCP_UNALINGED

#include "lwip/opt.h"
// TODO:: consider if this can replace the get_unaligned_be16 in unalinged.h?
static inline u16_t get_unaligned_be16(const void *p)
{
    u16_t tmp;
    MEMMOVE(&tmp, p, 2);
    return tmp;
}

static inline u32_t get_unaligned_be32(const void *p)
{
    u32_t tmp;
    MEMMOVE(&tmp, p, 4);
    return tmp;

}

static inline u64_t get_unaligned_be64(const void *p)
{
    u64_t tmp;
    MEMMOVE(&tmp, p, 8);
    return tmp;
}
#endif /* _LINUX_UNALIGNED*/

