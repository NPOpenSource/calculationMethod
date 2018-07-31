/******************************************************************************
NAME  =  CMyMutex.h
FUNC  =
NOTE  =
DATE  =  2017-04-13 ;
AUTH  =  cuiql;
HIST  =  2017-04-13, (cuiql), Original ;
Copyright (C) TS, All rights reserved.
*******************************************************************************/
#ifndef _CMYMUTEX_H_
#define _CMYMUTEX_H_
#include <pthread.h>
class CMyMutex
{
private:
    pthread_mutex_t m_Mutex;            // Alias name of the mutex to be protected
    int m_iLocked;                       // Locking status
public:
    CMyMutex();
    ~CMyMutex();
    int Lock();
    void Unlock();
};
#endif
