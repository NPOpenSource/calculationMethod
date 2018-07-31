/*===========================================================================

                         random.c

DESCRIPTION
The random number generator



Copyright (c) 2017.04 - 2017.05 Technologies, Incorporated.  All Rights Reserved.
===========================================================================*/

#include <lwip/arch/cc.h>
#include <lwip/def.h>

/*
 * Generate random number
 *
 * @parameter void * - buf
 * @parameter int - nbytes
 */
void get_random_bytes(void *buf, int nbytes)
{

  u32_t new_rand, n;
  unsigned char *ptr = (unsigned char *)buf;

  while (nbytes > 0) {
    new_rand = LWIP_RAND();
    n = LWIP_MIN(nbytes, sizeof(new_rand));
    MEMCPY(ptr, &new_rand, n);
    ptr += n;
    nbytes -= n;
  }
}