/******************************************************************************
NAME  =	 CMyMutex.cpp
FUNC  =
NOTE  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
Copyright (C) TS, All rights reserved.
*******************************************************************************/
#include "CMyMutex.h"
/******************************************************************************
NAME  =	 CMyMutex() ;
FUNC  =	 constructed function;
INPUT =
RETU  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
*******************************************************************************/
CMyMutex::CMyMutex()
{
	pthread_mutex_init(&m_Mutex, NULL);
}
/******************************************************************************
NAME  =	 ~CMyMutex() ;
FUNC  =	 destructor;
INPUT =
RETU  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
*******************************************************************************/
CMyMutex::~CMyMutex()
{
	pthread_mutex_destroy(&m_Mutex);
}
	
/******************************************************************************
NAME  =	 Lock() ;
FUNC  =	 lock ;
INPUT =
RETU  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
*******************************************************************************/
int CMyMutex::Lock()
{
	m_iLocked = pthread_mutex_lock(&m_Mutex);
	return m_iLocked;
}
/******************************************************************************
NAME  =	 Unlock() ;
FUNC  =	 unlock ;
INPUT =
RETU  =
DATE  =	 2017-04-13 ;
AUTH  =	 cuiql;
HIST  =	 2017-04-13, (cuiql), Original ;
*******************************************************************************/
void CMyMutex::Unlock()
{
      if (0 == m_iLocked)
         pthread_mutex_unlock(&m_Mutex);
}
