#ifndef __PREFIX_TAGS_H_
#define __PREFIX_TAGS_H_


#define DEBUG 1
#define debug_print(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)

static const int INTERFACE_IN = 0;
static const int INTERFACE_OUT = 1;

#endif // __PREFIX_TAGS_H_
