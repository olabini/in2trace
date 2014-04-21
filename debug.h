#ifndef _DEBUG_H_
#define _DEBUG_H_

typedef enum {
	dlFatal = 0, dlError, dlWarn, dlInfo, dlDetails, dlDebug
} debug_level_t;

/* Function prints debug string on given debug level */
extern int _debug_printf(debug_level_t dl, const char *file, const char *func, int line, const char *fmt, ...);

/* Better wrapper */
#define debug_printf(dl, ...) _debug_printf(dl, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);

/* Function initializes debug */
extern int _debug_init(debug_level_t dl, char *l);

#endif
