#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <wicked/util.h>
#include "dhcp6/options.h"

int main(int argc, char *argv[])
{
	ni_dhcp6_ia_t *list = NULL, **pos, *ia;
	unsigned int i = 0;

	ni_dhcp6_ia_list_append(&list, ni_dhcp6_ia_na_new(++i));
	ni_dhcp6_ia_list_append(&list, ni_dhcp6_ia_pd_new(++i));
	ni_dhcp6_ia_list_append(&list, ni_dhcp6_ia_na_new(++i));
	ni_dhcp6_ia_list_append(&list, ni_dhcp6_ia_ta_new(++i));
	ni_dhcp6_ia_list_append(&list, ni_dhcp6_ia_pd_new(++i));
	ni_dhcp6_ia_list_append(&list, ni_dhcp6_ia_na_new(++i));

	for (i = 0, ia = list; ia; ++i, ia = ia->next) {
		printf("[%u]: ia iaid: %u, type %u\n", i, ia->iaid, ia->type);
	}
	pos = &list;
	while ((ia = *pos)) {
		if (ni_dhcp6_ia_type_na(ia)) {
			*pos = ia->next;
			printf("free iaid %u type %u\n", ia->iaid, ia->type);
			ni_dhcp6_ia_free(ia);
		} else {
			pos = &ia->next;
			printf("keep iaid %u type %u\n", ia->iaid, ia->type);
		}
	}

	for (i = 0, ia = list; ia; ++i, ia = ia->next) {
		printf("[%u]: ia iaid: %u, type %u\n", i, ia->iaid, ia->type);
	}
	return 0;
}
