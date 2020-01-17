
#include <stdio.h>
#include <wicked/dbus-service.h>
#include <wicked/dbus-errors.h>

#include "dbus-dict.h"
#include "dbus-common.h"
#include "dbus-objects/model.h"
#include "useless.h"

#define NI_USELESS_BUS_NAME			"org.opensuse.Network.Useless"
#define NI_USELESS_OBJECT_PATH			"/org/opensuse/Network/Useless"
#define NI_USELESS_INTERFACE			"org.opensuse.Network.Useless"

#define NI_USELESS_CALL_PRINT			"Print"

typedef struct ni_useless_client_ops {
	int	(*useless_print)(ni_useless_client_t *, char *);
} ni_useless_client_ops_t;

struct ni_useless_client {
	ni_useless_client_ops_t	ops;
	char *			instance;

	/* dbus */
	ni_dbus_client_t *	dbus;
	ni_dbus_object_t *	proxy;

	/* unix */
	ni_shellcmd_t *		cmd;
};

int
ni_do_useless(int argc, char **argv)
{
	printf("Hello useless world!\n");

        return 0;
}

ni_useless_client_t *
ni_useless_client_open(const char *instance)
{
	ni_useless_client_t *uc;
	char *busname = NULL;

	if (!ni_useless_enabled(instance))
		return NULL;

	if (ni_string_empty(instance))
		return NULL;

	uc = xcalloc(1, sizeof(*uc));
	ni_string_dup(&uc->instance, instance);

	if (!ni_useless_dbus_client_init(uc, busname))
		goto failure;

	ni_string_free(&busname);
	return uc;

failure:
	ni_string_free(&busname);
	ni_useless_client_free(uc);
	return NULL;
}

static ni_dbus_class_t		ni_objectmodel_useless_client_class = {
	.name = "useless-client"
};

static const ni_intmap_t	ni_useless_dbus_error_names[] = {
	{ NULL,			-1			}
};

static ni_bool_t
ni_useless_dbus_client_init(ni_useless_client_t *uc, const char *busname)
{
	uc->dbus = ni_dbus_client_open("system", busname);
	if (!uc->dbus)
		return FALSE;

	ni_dbus_client_set_error_map(uc->dbus, ni_useless_dbus_error_names);
	uc->proxy = ni_dbus_client_object_new(uc->dbus,
			&ni_objectmodel_useless_client_class,
			NI_USELESS_OBJECT_PATH, NI_USELESS_INTERFACE, uc);
	if (!uc->proxy)
		return FALSE;
	ni_dbus_client_add_signal_handler(uc->dbus,
				NI_USELESS_BUS_NAME,	/* sender */
				NULL,			/* object path */
				NI_USELESS_INTERFACE,	/* object interface */
				ni_useless_dbus_signal,
				uc);
	return TRUE;
}

static void
ni_useless_dbus_client_destroy(ni_useless_client_t *uc)
{
	if (uc->dbus) {
		ni_dbus_client_free(uc->dbus);
		uc->dbus = NULL;
	}

	if (uc->proxy) {
		ni_dbus_object_free(uc->proxy);
		uc->proxy = NULL;
	}
}

static void
ni_useless_dbus_signal(ni_dbus_connection_t *connection, ni_dbus_message_t *msg, void *user_data)
{
	/* ni_useless_client_t *uc = user_data; */
	const char *member = dbus_message_get_member(msg);

	ni_debug_dbus("useless-client: %s signal received (not handled)", member);
}

static int
ni_useless_dbus_print(ni_useless_client_t *uc, char **result)
{
	int rv;

	if (!result)
		return -NI_ERROR_INVALID_ARGS;

	rv = ni_dbus_object_call_simple(uc->proxy,
		NI_USELESS_INTERFACE, NI_USELESS_CALL_PRINT,
		0, NULL,
		DBUS_TYPE_STRING, result);

	if (rv < 0) {
		ni_debug_application("Call to %s."NI_USELESS_CALL_PRINT"() failed: %s",
			ni_dbus_object_get_path(uc->proxy), ni_strerror(rv));
	}

	return rv;
}