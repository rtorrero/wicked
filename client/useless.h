/*
 *	Just crap. Testing time :-)
 *
 */
#ifndef   __WICKED_CLIENT_USELESS_H__
#define   __WICKED_CLIENT_USELESS_H__

#include <wicked/types.h>

typedef struct ni_useless_client		ni_useless_client_t;

ni_useless_client_t *			ni_useless_client_open(const char*);
void					ni_useless_client_free(ni_useless_client_t *);

extern int	                	ni_do_useless(int argc, char **argv);

#endif /* __WICKED_CLIENT_USELESS_H__ */
