/*
 * iperf, Copyright (c) 2014, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 *
 * Based on timers.c by Jef Poskanzer. Used with permission.
 */

#include <sys/types.h>
#include <stdlib.h>

#include "timer.h"
#include "iperf_key.h"
#include "iperf.h"

TimerClientData JunkClientData;



/* This is an efficiency tweak.  All the routines that need to know the
** current time get passed a pointer to a struct timeval.  If it's non-NULL
** it gets used, otherwise we do our own gettimeofday() to fill it in.
** This lets the caller avoid extraneous gettimeofday()s when efficiency
** is needed, and not bother with the extra code when efficiency doesn't
** matter too much.
*/
static void
getnow( struct timeval* nowP, struct timeval* nowP2 )
{
    if ( nowP != NULL )
	*nowP2 = *nowP;
    else
	(void) gettimeofday( nowP2, NULL );
}


static void
list_add( Timer* t )
{
    Timer* t2;
    Timer* t2prev;
    struct iperf_test *test = getGlobalIperfInThread();
    if ( test->timers == NULL ) {
	/* The list is empty. */
	    test->timers = t;
	    t->prev = t->next = NULL;
    } else {
	if ( t->time.tv_sec < test->timers->time.tv_sec ||
	     ( t->time.tv_sec == test->timers->time.tv_sec &&
	       t->time.tv_usec < test->timers->time.tv_usec ) ) {
	    /* The new timer goes at the head of the list. */
	    t->prev = NULL;
	    t->next = test->timers;
        test->timers->prev = t;
        test->timers = t;
	} else {
	    /* Walk the list to find the insertion point. */
	    for ( t2prev = test->timers, t2 = test->timers->next; t2 != NULL;
		  t2prev = t2, t2 = t2->next ) {
		if ( t->time.tv_sec < t2->time.tv_sec ||
		     ( t->time.tv_sec == t2->time.tv_sec &&
		       t->time.tv_usec < t2->time.tv_usec ) ) {
		    /* Found it. */
		    t2prev->next = t;
		    t->prev = t2prev;
		    t->next = t2;
		    t2->prev = t;
		    return;
		}
	    }
	    /* Oops, got to the end of the list.  Add to tail. */
	    t2prev->next = t;
	    t->prev = t2prev;
	    t->next = NULL;
	}
    }
}


static void
list_remove( Timer* t )
{
    struct iperf_test *test = getGlobalIperfInThread();
    if ( t->prev == NULL )
        test->timers = t->next;
    else
	t->prev->next = t->next;
    if ( t->next != NULL )
	t->next->prev = t->prev;
}


static void
list_resort( Timer* t )
{
    /* Remove the timer from the list. */
    list_remove( t );
    /* And add it back in, sorted correctly. */
    list_add( t );
}


static void
add_usecs( struct timeval* t, int64_t usecs )
{
    t->tv_sec += usecs / 1000000L;
    t->tv_usec += usecs % 1000000L;
    if ( t->tv_usec >= 1000000L ) {
	t->tv_sec += t->tv_usec / 1000000L;
	t->tv_usec %= 1000000L;
    }
}


Timer*
tmr_create(
    struct timeval* nowP, TimerProc* timer_proc, TimerClientData client_data,
    int64_t usecs, int periodic )
{
    struct timeval now;
    Timer* t;
    struct iperf_test *test = getGlobalIperfInThread();
    getnow( nowP, &now );

    if ( test->free_timers != NULL ) {
	t = test->free_timers;
	test->free_timers = t->next;
    } else {
	t = (Timer*) malloc( sizeof(Timer) );
	if ( t == NULL )
	    return NULL;
    }

    t->timer_proc = timer_proc;
    t->client_data = client_data;
    t->usecs = usecs;
    t->periodic = periodic;
    t->time = now;
    add_usecs( &t->time, usecs );
    /* Add the new timer to the active list. */
    list_add( t );

    return t;
}


struct timeval*
tmr_timeout( struct timeval* nowP )
{
    struct timeval now;
    int64_t usecs;
    static struct timeval timeout;
    struct iperf_test *test = getGlobalIperfInThread();
    getnow( nowP, &now );
    /* Since the list is sorted, we only need to look at the first timer. */
    if ( test->timers == NULL )
	return NULL;
    usecs = ( test->timers->time.tv_sec - now.tv_sec ) * 1000000LL +
	    ( test->timers->time.tv_usec - now.tv_usec );
    if ( usecs <= 0 )
	usecs = 0;
    timeout.tv_sec = usecs / 1000000LL;
    timeout.tv_usec = usecs % 1000000LL;
    return &timeout;
}


void
tmr_run( struct timeval* nowP )
{
    struct timeval now;
    Timer* t;
    Timer* next;
    struct iperf_test *test = getGlobalIperfInThread();
    getnow( nowP, &now );
    for ( t = test->timers; t != NULL; t = next ) {
	next = t->next;
	/* Since the list is sorted, as soon as we find a timer
	** that isn't ready yet, we are done.
	*/
	if ( t->time.tv_sec > now.tv_sec ||
	     ( t->time.tv_sec == now.tv_sec &&
	       t->time.tv_usec > now.tv_usec ) )
	    break;
	(t->timer_proc)( t->client_data, &now );
	if ( t->periodic ) {
	    /* Reschedule. */
	    add_usecs( &t->time, t->usecs );
	    list_resort( t );
	} else
	    tmr_cancel( t );
    }
}


void
tmr_reset( struct timeval* nowP, Timer* t )
{
    struct timeval now;
    
    getnow( nowP, &now );
    t->time = now;
    add_usecs( &t->time, t->usecs );
    list_resort( t );
}


void
tmr_cancel( Timer* t )
{
    struct iperf_test *test = getGlobalIperfInThread();
    /* Remove it from the active list. */
    list_remove( t );
    /* And put it on the free list. */
    t->next = test->free_timers;
    test->free_timers = t;
    t->prev = NULL;
}


void
tmr_cleanup( void )
{
    Timer* t;
    struct iperf_test *test = getGlobalIperfInThread();
    while ( test->free_timers != NULL ) {
	t = test->free_timers;
	test->free_timers = t->next;
	free( (void*) t );
    }
}


void
tmr_destroy( void )
{
    struct iperf_test *test = getGlobalIperfInThread();
    while ( test->timers != NULL )
	tmr_cancel( test->timers );
    tmr_cleanup();
}
