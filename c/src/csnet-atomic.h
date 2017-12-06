#pragma once

#define ACCESS_ONCE(x) (*((volatile __typeof__(x) *) &x))
#define INC_ONE_ATOMIC(x) __sync_fetch_and_add(x, 1)
#define DEC_ONE_ATOMIC(x) __sync_fetch_and_sub(x, 1)
#define INC_N_ATOMIC(x, n) __sync_fetch_and_add(x, n)

#define CAS __sync_bool_compare_and_swap

#define CPU_BARRIER __sync_synchronize
#define COMPILER_BARRIER() __asm__ __volatile__("" : : : "memory")

