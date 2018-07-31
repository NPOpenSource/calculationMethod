//
// Created by user on 4/14/17.
//

#include <lwip/timeouts.h>
#include "test_inout.h"

void test(void* a)
{
    TSLOG("TIMER","OK", NULL);

    sys_timeout(5000, test, NULL);
}

void test_timer()
{

    TSLOG("TIMER","NOW", NULL);
    sys_timeout(5000, test, NULL);
}