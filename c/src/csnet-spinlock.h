#pragma once

typedef int csnet_spinlock_t;

static inline void
csnet_spinlock_init(csnet_spinlock_t* lock) {
	*lock = 0;
}

static inline void
csnet_spinlock_lock(csnet_spinlock_t* lock) {
	while (__sync_lock_test_and_set(lock, 1));
}

static inline int
csnet_spinlock_trylock(csnet_spinlock_t* lock) {
	return __sync_lock_test_and_set(lock, 1) == 0;
}

static inline void
csnet_spinlock_unlock(csnet_spinlock_t* lock) {
	__sync_lock_release(lock);
}

