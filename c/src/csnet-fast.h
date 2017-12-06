#pragma once

/*
 * See GCC-5.2 manual 
 * 6.57 Other Built-in Functions Provided by GCC
 *  long __builtin_expect (long exp, long c)
 * for more details.
 */

#if defined __GUN__
# define csnet_fast(x) __builtin_expect(!!(x), 1)
# define csnet_slow(x) __builtin_expect(!!(x), 0)
#else
# define csnet_fast(x) (x)
# define csnet_slow(x) (x)
#endif

