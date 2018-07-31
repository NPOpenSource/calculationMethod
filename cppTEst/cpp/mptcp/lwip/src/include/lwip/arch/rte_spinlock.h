//
// Created by ts on 2017/10/14.
//

#ifndef MYAPPLICATION_RTE_SPINLOCK_H
#define MYAPPLICATION_RTE_SPINLOCK_H

#include "rte_ring.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The rte_spinlock_t type.
 */
typedef struct {
    volatile int locked; /**< lock status 0 = unlocked, 1 = locked */
} rte_spinlock_t;

/**
 * A static spinlock initializer.
 */
#define RTE_SPINLOCK_INITIALIZER { 0 }

/**
 * Initialize the spinlock to an unlocked state.
 *
 * @param sl
 *   A pointer to the spinlock.
 */
static inline void
rte_spinlock_init(rte_spinlock_t *sl)
{
    sl->locked = 0;
}

static inline void
rte_spinlock_lock(rte_spinlock_t *sl)
{
    while (__sync_lock_test_and_set(&sl->locked, 1))
        while(sl->locked)
            rte_pause();
}

static inline int
rte_spinlock_trylock(rte_spinlock_t *sl)
{
    return __sync_lock_test_and_set(&sl->locked,1) == 0;
}

static inline void
rte_spinlock_unlock (rte_spinlock_t *sl)
{
    __sync_lock_release(&sl->locked);
}

#ifdef __cplusplus
};
#endif
#endif //MYAPPLICATION_RTE_SPINLOCK_H
