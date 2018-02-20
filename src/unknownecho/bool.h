#ifndef UNKNOWNECHO_BOOL_H
#define UNKNOWNECHO_BOOL_H

/* C99 */
#if __STDC_VERSION__ >= 199901L

#include <stdbool.h>

#else /* Not C99 */

typedef enum {
    false,
    true
} bool;

#endif

#endif /* BOOL_H */
