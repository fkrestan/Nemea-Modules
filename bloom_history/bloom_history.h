#ifndef __BLOOM_HISTORY_H_
#define __BLOOM_HISTORY_H_

static const int INTERFACE_IN = 0;

#define DEBUG 1
#define debug_print(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)

#endif // __BLOOM_HISTORY_H_
