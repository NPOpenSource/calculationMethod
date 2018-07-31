//
// Created by ts on 17-7-25.
//

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "common.h"
#include <sys/time.h>
#include "irandom.h"
unsigned long read_random() {
#if 0
    int i, fd;
    const char *dev = "/dev/random";
    unsigned long ret = 0;
    unsigned long tmp = 0;

    LogI("%s:%d: enter", __FUNCTION__, __LINE__);
    fd = open( dev, O_RDONLY );

    if( fd == -1 ) {
        LogE("open random fails");
        return 0;
    }
    if(-1 == read( fd, &ret, sizeof(unsigned long)))
    {
        LogE("read random fials");
        close(fd);
        return 0;
    }
    LogI("random:%d",ret);
    close( fd );
    LogI("%s:%d: leave", __FUNCTION__, __LINE__);
    return ret;
#else
    static unsigned long factor = 0xa5a55a5aUL;
    unsigned long sec;
    unsigned long usec;
    unsigned long result;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    sec = (unsigned long)tv.tv_sec;
    usec = (unsigned long)tv.tv_usec;
    result = factor * (sec * 1000000 + usec);
    factor++;
    if(factor == 0)
        factor++;
    return result;
#endif
}
