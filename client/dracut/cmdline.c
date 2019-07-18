/*
 *	wicked client configuration reading for dracut cmdline schema.
 *
 *	Copyright (C) 2018 SUSE LINUX GmbH, Nuernberg, Germany.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *	Authors:
 *		Rubén Torrero Marijnissen <rtorreromarijnissen@suse.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include <wicked/util.h>
#include <wicked/logging.h>
#include <wicked/netinfo.h>
#include <wicked/ipv4.h>
#include <wicked/ipv6.h>
#include <wicked/xml.h>
#include <wicked/vlan.h>

#include "client/wicked-client.h"
#include "cmdline.h"
#include "client/ifconfig.h"
#include "util_priv.h"
#include "buffer.h"

static const ni_intmap_t        dracut_params[] = {
	{ "ifname",             NI_DRACUT_PARAM_IFNAME  },
	{ "bridge",             NI_DRACUT_PARAM_BRIDGE  },
	{ "bond",               NI_DRACUT_PARAM_BOND    },
	{ "vlan",               NI_DRACUT_PARAM_VLAN    },
	{ "ip",			NI_DRACUT_PARAM_IP	},
	{ NULL,                 -1U                     },
};

ni_bool_t
ni_test_crap(const ni_compat_netdev_array_t *param1, const char *param2)
{
	printf("hello I'm working fine :-)\n");

	return TRUE;
}

ni_bool_t
ni_dracut_param_type(const char *name, unsigned int *param)
{
        return ni_parse_uint_mapped(name, dracut_params, param) == 0;
}

const char *
ni_dracut_param_name(unsigned int *param)
{
        return ni_format_uint_mapped(*param, dracut_params);
}

static inline unsigned int param_find(const ni_var_array_t *params, unsigned int pos, const ni_var_t *var)
{
	return ni_var_array_find(params, pos, var, ni_var_name_equal, NULL);
}

static char * __ni_suse_default_hostname;

//FIXME: Like described below, this is duplicated, move this to a common place for both compat-suse.c and cmdline.c
const char * ni_compat_read_default_hostname(const char *root, char **hostname);

ni_compat_netdev_t *
ni_cmdlineconfig_new_compat_netdev(const char *filename)
{
	ni_compat_netdev_t *compat = NULL;

	compat = ni_compat_netdev_new(NULL);
	ni_compat_netdev_set_origin(compat, "dracut:cmdline", filename);

	return compat;
}

ni_bool_t
ni_cmdlineconfig_append_compat_netdev(ni_compat_netdev_array_t *nd, ni_compat_netdev_t *compat)
{
	/**
	 *  Check if the interface has already been added.
	 *  FIXME: we need to be able to append certain properties
	 *  to existing devices
	 */
	if (compat->dev->name != NULL && (ni_compat_netdev_by_name(nd, compat->dev->name))) {
		ni_error("Duplicated ip= parameters for the same device!");
		return FALSE;
	};

	ni_compat_netdev_array_append(nd, compat);

	// FIXME: Probably useless at this point
	compat->firewall.enabled = TRUE;

	return TRUE;
}

ni_bool_t
ni_cmdlineconfig_parse_opt_ip_method(ni_compat_netdev_t *compat, const char *method){
	ni_bool_t rv = FALSE;
	ni_ipv4_devinfo_t *ipv4;
	ni_ipv6_devinfo_t *ipv6;

	if (!strcmp(method, "dhcp")) {
		ipv4 = ni_netdev_get_ipv4(compat->dev);
		ni_tristate_set(&ipv4->conf.enabled, TRUE);
		ni_tristate_set(&ipv4->conf.arp_verify, TRUE);

		compat->dhcp4.enabled = TRUE;
		ni_addrconf_update_set(&compat->dhcp4.update, NI_ADDRCONF_UPDATE_HOSTNAME, TRUE);
		ni_addrconf_update_set(&compat->dhcp4.update, NI_ADDRCONF_UPDATE_SMB, TRUE);

		//FIXME: read default as compat-suse.c does?
		compat->dhcp4.defer_timeout = 15;

		ni_compat_read_default_hostname("", &__ni_suse_default_hostname);
		ni_string_dup(&compat->dhcp4.hostname, __ni_suse_default_hostname);
		rv = TRUE;

	} else if (!strcmp(method, "dhcp6")) {
		ipv6 = ni_netdev_get_ipv6(compat->dev);
		ni_tristate_set(&ipv6->conf.enabled, TRUE);

		compat->dhcp6.enabled = TRUE;
		ni_compat_read_default_hostname("", &__ni_suse_default_hostname);
		rv = TRUE;

	} else if (!strcmp(method, "auto6")) {
		ipv6 = ni_netdev_get_ipv6(compat->dev);
		ni_tristate_set(&ipv6->conf.enabled, TRUE);

		compat->auto6.enabled = TRUE;

	} else if (!strcmp(method, "either6")) {
		ipv6 = ni_netdev_get_ipv6(compat->dev);
		ni_tristate_set(&ipv6->conf.enabled, TRUE);

		// FIXME: If auto fails, and only then, use dhcp6
		compat->auto6.enabled = TRUE;
		compat->dhcp6.enabled = TRUE;

	} else if (!strcmp(method, "on")) {
		ni_error("FIXME: Not sure how to handle 'on' config method");

	} else if (!strcmp(method, "any")) {
		ni_error("FIXME: Not sure how to handle 'any' config method");
	}

	return rv;
}

/**
 * This function decomposes the value of a ni_var_t param into multiple
 * strings to an ni_string_array
 */
ni_bool_t
ni_cmdlineconfig_decompose_param(ni_var_t *param, ni_string_array_t *sa)
{
	const char delim[2] = ":";
	const char *ptr;

	if (!param || !sa)
		return FALSE;

	ptr = param->value;

	while (ptr) {
		ni_string_array_append_until(sa, ptr, strcspn(ptr, ":"));
		strchr(ptr, ":");
	}
	return TRUE;
}

ni_bool_t
ni_cmdlineconfig_parse_opt_ip_new(ni_compat_netdev_t *compat, ni_var_t *param)
{
	int rv = NI_CMDLINE_SYNTAX_INVALID;
	ni_sockaddr_t addr;
	unsigned int prefixlen = ~0U;
	// FIXME: Duplicating the ipv4 ipv6 stuff here is not cool
	ni_ipv4_devinfo_t *ipv4;
	ni_ipv6_devinfo_t *ipv6;
	const char *ifname = NULL;
	ni_string_array_t subparams = NI_STRING_ARRAY_INIT;

	if (!param)
		return FALSE;

	ni_cmdlineconfig_decompose_param(param, &subparams);

	// if (!ni_sockaddr_prefix_parse(param->data[0], &addr, &prefixlen)) {
	// 	if (params->count < 2) {

	// 		// This is the ip=<conf-method> syntax
	// 		if (!ni_cmdlineconfig_parse_opt_ip_method(compat, params->data[0]))
	// 			rv = NI_CMDLINE_SYNTAX_INVALID;
	// 		else
	// 			rv = NI_CMDLINE_SYNTAX_SIMPLE;

	// 	} else {

	// 		//This is the ip=<interface>:... case
	// 		if (!ni_cmdlineconfig_parse_opt_ip_method(compat, params->data[1])) {
	// 			rv = NI_CMDLINE_SYNTAX_INVALID;
	// 		} else {
	// 			ifname = params->data[0];
	// 			rv = NI_CMDLINE_SYNTAX_SIMPLE_IFNAME;
	// 		}
	// 	}
	// } else {
	// 	// FIXME: Finish this syntax implementation and check
	// 	// (two cases actually here, the one with DNS at the end and the one with MTU and macaddr, just one for now)
	// 	// ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}
	// 	if (addr.ss_family == AF_INET) {
	// 		ipv4 = ni_netdev_get_ipv4(compat->dev);
	// 		ni_tristate_set(&ipv4->conf.enabled, TRUE);
	// 		ni_tristate_set(&ipv4->conf.arp_verify, TRUE);
	// 	} else if (addr.ss_family == AF_INET6) {
	// 		ipv6 = ni_netdev_get_ipv6(compat->dev);
	// 		ni_tristate_set(&ipv6->conf.enabled, TRUE);
	// 	}
	// 	ni_address_new(addr.ss_family, prefixlen, &addr, &compat->dev->addrs);
	// 	ifname = params->data[5];
	// 	rv = NI_CMDLINE_SYNTAX_EXPLICIT_DNS;
	// }

	// // Add the interface name
	// compat->dev->name = xstrdup(ifname);
	// return rv;
}

/** Here we return an int so that we let the caller know what type of ip= format
 * was used and interface name can be set appropiately*/
int
ni_cmdlineconfig_parse_opt_ip(ni_compat_netdev_t *compat, ni_string_array_t *params, const char *filename)
{
	int rv = NI_CMDLINE_SYNTAX_INVALID;
	ni_sockaddr_t addr;
	unsigned int prefixlen = ~0U;
	// FIXME: Duplicating the ipv4 ipv6 stuff here is not cool
	ni_ipv4_devinfo_t *ipv4;
	ni_ipv6_devinfo_t *ipv6;
	const char *ifname = NULL;

	if (!params)
		return FALSE;

	if (!ni_sockaddr_prefix_parse(params->data[0], &addr, &prefixlen)) {
		if (params->count < 2) {

			// This is the ip=<conf-method> syntax
			if (!ni_cmdlineconfig_parse_opt_ip_method(compat, params->data[0]))
				rv = NI_CMDLINE_SYNTAX_INVALID;
			else
				rv = NI_CMDLINE_SYNTAX_SIMPLE;

		} else {

			//This is the ip=<interface>:... case
			if (!ni_cmdlineconfig_parse_opt_ip_method(compat, params->data[1])) {
				rv = NI_CMDLINE_SYNTAX_INVALID;
			} else {
				ifname = params->data[0];
				rv = NI_CMDLINE_SYNTAX_SIMPLE_IFNAME;
			}
		}
	} else {
		// FIXME: Finish this syntax implementation and check
		// (two cases actually here, the one with DNS at the end and the one with MTU and macaddr, just one for now)
		// ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}
		if (addr.ss_family == AF_INET) {
			ipv4 = ni_netdev_get_ipv4(compat->dev);
			ni_tristate_set(&ipv4->conf.enabled, TRUE);
			ni_tristate_set(&ipv4->conf.arp_verify, TRUE);
		} else if (addr.ss_family == AF_INET6) {
			ipv6 = ni_netdev_get_ipv6(compat->dev);
			ni_tristate_set(&ipv6->conf.enabled, TRUE);
		}
		ni_address_new(addr.ss_family, prefixlen, &addr, &compat->dev->addrs);
		ifname = params->data[5];
		rv = NI_CMDLINE_SYNTAX_EXPLICIT_DNS;
	}

	// Add the interface name
	compat->dev->name = xstrdup(ifname);
	return rv;
}

ni_bool_t
ni_cmdlineconfig_parse_vlan(ni_compat_netdev_t *compat, ni_string_array_t *params)
{
	ni_vlan_t *vlan;
	const char *ifname;
	const char *etherdev;
	const char *vlantag;
	unsigned int tag = 0;
	size_t len;


	if (params->count != 2) {
		ni_error("Wrong number of params for vlan specification!");
		return FALSE;
	}

	ifname = params->data[0];
	etherdev = params->data[1];

	if (ifname && !ni_netdev_name_is_valid(ifname)) {
		ni_error("Rejecting suspect interface name: %s", ifname);
		return FALSE;
	}

	compat->dev->link.type = NI_IFTYPE_VLAN;
	vlan = ni_netdev_get_vlan(compat->dev);

	if (!strcmp(ifname, etherdev)) {
		ni_error("ifcfg-%s: ETHERDEVICE=\"%s\" self-reference",
			ifname, etherdev);
		return FALSE;
	}

	if ((vlantag = strrchr(ifname, '.')) != NULL) {
		/* name.<TAG> */
		++vlantag;
	} else {
		/* name<TAG> */
		len = strlen(ifname);
		vlantag = &ifname[len];
		while(len > 0 && isdigit((unsigned char)vlantag[-1]))
			vlantag--;
	}

	if (ni_parse_uint(vlantag, &tag, 10) < 0) {
		ni_error("ifcfg-%s: Cannot parse vlan-tag from interface name",
			compat->dev->name);
		return FALSE;
	}
	vlan->protocol = NI_VLAN_PROTOCOL_8021Q;
	vlan->tag = tag;


	// Add the name
	compat->dev->name = xstrdup(ifname);

	return TRUE;
}
ni_bool_t
ni_cmdlineconfig_parse_team(ni_compat_netdev_array_t *nd, ni_string_array_t *params)
{
	//FIXME: Implement this
	return TRUE;
}

ni_bool_t
ni_cmdlineconfig_parse_bond(ni_compat_netdev_array_t *nd, ni_string_array_t *params)
{
	//FIXME: Implement this
	return TRUE;
}

ni_bool_t
ni_cmdlineconfig_parse_bridge(ni_compat_netdev_t *compat, ni_string_array_t *params)
{
	//FIXME: Implement this
	return TRUE;
}

/** TODO:
 * cleanup function with similar functionality to ni_cmdlineconfig_add_interface
 */
ni_bool_t
ni_cmdlineconfig_parse_cmdline_var(ni_compat_netdev_array_t *nd, const char *name, ni_string_array_t *params, const char *filename)
{
	ni_compat_netdev_t *compat = NULL;

	if (name == NULL)
		return FALSE;


	if (!strcmp(name, "ip")) {
		compat = ni_cmdlineconfig_new_compat_netdev(filename);
		if (!compat || !ni_cmdlineconfig_parse_opt_ip(compat, params, filename))
			goto cleanup;

		ni_cmdlineconfig_append_compat_netdev(nd, compat);
	} else if (!strcmp(name, "root")) {
		return TRUE;
	} else if (!strcmp(name, "ifname")) {
		return TRUE;
	} else if (!strcmp(name, "rd.route")) {
		return TRUE;
	} else if (!strcmp(name, "bootdev")) {
		return TRUE;
	} else if (!strcmp(name, "BOOTIF")) {
		return TRUE;
	} else if (!strcmp(name, "rd.bootif")) {
		return TRUE;
	} else if (!strcmp(name, "nameserver")) {
		return TRUE;
	} else if (!strcmp(name, "rd.peerdns")) {
		return TRUE;
	} else if (!strcmp(name, "vlan")) {
		compat = ni_cmdlineconfig_new_compat_netdev(filename);
		if (!compat || !ni_cmdlineconfig_parse_vlan(compat, params))
			goto cleanup;

		ni_cmdlineconfig_append_compat_netdev(nd, compat);
	} else if (!strcmp(name, "bond")) {
		ni_cmdlineconfig_parse_bond(nd, params);
	} else if (!strcmp(name, "team")) {
		ni_cmdlineconfig_parse_team(nd, params);
	} else if (!strcmp(name, "bridge")) {
		compat = ni_cmdlineconfig_new_compat_netdev(filename);
		if (!compat || !ni_cmdlineconfig_parse_bridge(compat, params))
			goto cleanup;

		ni_cmdlineconfig_append_compat_netdev(nd, compat);
	}

	return TRUE;

cleanup:
	ni_compat_netdev_free(compat);
	return FALSE;
}

/**
 * parse 'ip="foo bar" blub=hoho' lines with key[=<quoted-value|value>]
 * @return <0 on error, 0 when param extracted, >0 to skip/ignore (crap or empty param)
 */
static int
ni_dracut_cmdline_param_parse_and_unquote(ni_stringbuf_t *param, ni_buffer_t *buf)
{
	int quote = 0, esc = 0, parse = 0, cc;

	while ((cc = ni_buffer_getc(buf)) != EOF) {
		if (parse) {
			if (quote) {
				if (esc) {
					/* only \" for now */
					ni_stringbuf_putc(param, cc);
					esc = 0;
				} else
				if (cc == '\\') {
					esc = cc;
				} else
				if (cc == quote)
					quote = 0;
				else
					ni_stringbuf_putc(param, cc);
			} else {
				if (cc == '\'')
					quote = cc;
				else
				if (cc == '"')
					quote = cc;
				else
				if (isspace((unsigned int)cc))
					return FALSE;
				else
					ni_stringbuf_putc(param, cc);
			}
		} else {
			/* skip spaces before/after */
			if (isspace((unsigned int)cc))
				continue;

			parse = 1;
			ni_stringbuf_putc(param, cc);
		}
	}

	return param->len == 0;
}

/**
 * This function adds an interface to the ni_compat_netdev_array
 * structure. It should also check only for supported configuration values
 * Maybe should be renamed to ni_cmdlineconfig_parse_value or something?
 */
ni_bool_t
ni_cmdlineconfig_add_interface(ni_compat_netdev_array_t *nd, const char *name, const char *value, const char *filename)
{
	char ifname[16];
	char varname_buf[19];
	char filtered_value[512];
	const char delim[2] = ":";
	char *token;
	ni_ipv4_devinfo_t *ipv4;
	ni_ipv6_devinfo_t *ipv6;
	ni_ifworker_control_t *control;
	size_t len;
	ni_compat_netdev_t *compat = NULL;

	int value_pos = 0;

	if (value) {
		strcpy(filtered_value, value);
//		unquote(filtered_value);
	}

	//FIXME: This should be parsed using strtok
	if (!strcmp(name, "ip")) {
		if (value && strchr(filtered_value, ':')) {
			len = strchr(filtered_value, ':') - filtered_value;
			strncpy(ifname, filtered_value, len);
			ifname[len] = 0;	// FIXME: not very safe if len is > than array size
			snprintf(varname_buf, sizeof varname_buf, "%s.%s", name, ifname);

			if (!ni_netdev_name_is_valid(ifname)) {
				ni_error("Rejecting suspect interface name: %s", ifname);
				return FALSE;
			}
			compat = ni_compat_netdev_new(ifname);

			ni_compat_netdev_array_append(nd, compat);
			token = strtok(filtered_value, delim);

			control = ni_ifworker_control_new();
			control->link_timeout = 0;
			compat->control = control;
			compat->firewall.enabled = TRUE;

			ni_compat_netdev_set_origin(compat, "dracut:cmdline", filename);

			while (token != NULL) {
				token = strtok(NULL, delim);
				value_pos++;
				if (token == NULL)
					break;
				if (!strcmp(token, "dhcp6")) {
					compat->dhcp6.enabled = TRUE;
					ipv6 = ni_netdev_get_ipv6(compat->dev);
					ipv4 = ni_netdev_get_ipv4(compat->dev);
					ni_tristate_set(&ipv6->conf.enabled, TRUE);
					ni_tristate_set(&ipv4->conf.enabled, TRUE);
					ni_tristate_set(&ipv4->conf.arp_verify, TRUE);
					ni_compat_read_default_hostname("", &__ni_suse_default_hostname);
					ni_string_dup(&compat->dhcp6.hostname, __ni_suse_default_hostname);
				} else if (!strcmp(token, "dhcp")) {
					compat->dhcp4.enabled = TRUE;
					ipv6 = ni_netdev_get_ipv6(compat->dev);
					ipv4 = ni_netdev_get_ipv4(compat->dev);
					ni_tristate_set(&ipv6->conf.enabled, TRUE);
					ni_tristate_set(&ipv4->conf.enabled, TRUE);
					ni_tristate_set(&ipv4->conf.arp_verify, TRUE);
					ni_addrconf_update_set(&compat->dhcp4.update, NI_ADDRCONF_UPDATE_HOSTNAME, TRUE);
					ni_addrconf_update_set(&compat->dhcp4.update, NI_ADDRCONF_UPDATE_SMB, TRUE);
					compat->dhcp4.defer_timeout = 15;	//FIXME: read default as compat-suse.c does
					ni_compat_read_default_hostname("", &__ni_suse_default_hostname);
					ni_string_dup(&compat->dhcp4.hostname, __ni_suse_default_hostname);
				} else if (!strcmp(token, "auto6")) {
					compat->auto6.enabled = TRUE;
					ipv6 = ni_netdev_get_ipv6(compat->dev);
					ipv4 = ni_netdev_get_ipv4(compat->dev);
					ni_tristate_set(&ipv6->conf.enabled, TRUE);
					ni_tristate_set(&ipv4->conf.enabled, TRUE);
					ni_tristate_set(&ipv4->conf.arp_verify, TRUE);
					ni_addrconf_update_set(&compat->auto6.update, NI_ADDRCONF_UPDATE_DNS, TRUE);
					compat->auto6.defer_timeout = 0;

				}
			}
			return TRUE;
		}
		// else ignore ip={dhcp|on|any|dhcp6|auto6} for now
	}

	return FALSE;
}


static ni_bool_t
ni_dracut_cmdline_line_parse(ni_var_array_t *params, ni_stringbuf_t *line)
{
	ni_stringbuf_t param = NI_STRINGBUF_INIT_DYNAMIC;
	char *name;
	char *value;
	ni_buffer_t buf;
	int ret;

	if (!params || !line)
		return FALSE;

	if (ni_string_empty(line->string))
		return TRUE;

	ni_buffer_init_reader(&buf, line->string, line->len);
	while (!(ret = ni_dracut_cmdline_param_parse_and_unquote(&param, &buf))) {
		if (ni_string_empty(param.string))
			continue;
		name = xstrdup(param.string);
		value = strchr(name, '=');
		if (*value != '\0') {
			*value = '\0';
			++value;
		} else {
			value = NULL;
		}
		ni_var_array_append(params, name, value);
		ni_stringbuf_clear(&param);
	}
	ni_stringbuf_destroy(&param);

	return ret != -1;
}

/**
 * Identify what function needs to be called to handle the supplied param
 **/
ni_bool_t
ni_dracut_cmdline_call_param_handler(ni_var_t *var, ni_compat_netdev_array_t *nd)
{
	switch ((var->value)) {
		case NI_DRACUT_PARAM_IP:
			printf("OMG ITS IP PARAM\n");
			ni_cmdlineconfig_parse_opt_ip_new(nd, var);
			break;
		default:
			printf("No idea what this crap is\n");
	}

	return TRUE;
}

/**
 * This function will apply the params found in the params array to the compat_netdev array
 */
static ni_bool_t
ni_dracut_cmdline_apply(const ni_var_array_t *params, ni_compat_netdev_array_t *nd)
{
	unsigned int i, pos;
	char *pptr;

	if (!params)
		return FALSE;

	for (i = 0; (pptr = (char *) ni_dracut_param_name(&i)); ++i) {
		const ni_var_t var = { .name = pptr, .value = NULL };
		pos = 0;
		while ((pos = ni_var_array_find(params, pos, &var, &ni_var_name_equal, NULL)) != -1U) {
			printf("%s is %s \n", pptr, params->data[pos].value);
			++pos;
		}
	}

	return TRUE;
}


/**
 * Read file and store into a ni_var_array all the params
 * that where found in filename
 *
 * Returns true/false whether it was correctly processed or not
 */
static ni_bool_t
ni_dracut_cmdline_file_parse(ni_var_array_t *params, const char *filename)
{
	ni_stringbuf_t line = NI_STRINGBUF_INIT_DYNAMIC;
	char buf[BUFSIZ], eol;
	size_t len;
	FILE *file;

	if (!params || ni_string_empty(filename))
		return FALSE;

	if (!(file = fopen(filename, "r")))
		return FALSE;

	memset(&buf, 0, sizeof(buf));
	while (fgets(buf, sizeof(buf), file)) {
		len = strcspn(buf, "\r\n");
		eol = buf[len];
		buf[len] = '\0';

		if (len) {
			fprintf(stdout, "fgets returned %zu bytes data: >%s<\n", len, buf);
			ni_stringbuf_puts(&line, buf);
		}
		if (eol) {
			ni_dracut_cmdline_line_parse(params, &line);
			ni_stringbuf_clear(&line);
		}
	}

	/* EOF while reading line with missing EOL termination */
	if (line.len) {
		ni_dracut_cmdline_line_parse(params, &line);
		ni_stringbuf_clear(&line);
	}

	ni_stringbuf_destroy(&line);
	fclose(file);
	return TRUE;
}

/** Main function, should read the dracut cmdline input and do mainly two things:
 *   - Parse the input and separate it in a string array where each string is exactly one config param
 *   - Construct the ni_compat_netdev struct
 */
ni_bool_t
ni_ifconfig_read_dracut_cmdline(xml_document_array_t *array, const char *type,
			const char *root, const char *path, ni_bool_t check_prio, ni_bool_t raw)
{
	unsigned int i;
	ni_compat_ifconfig_t conf;
	ni_compat_ifconfig_init(&conf, type);
	ni_var_array_t params = NI_VAR_ARRAY_INIT;

	if (ni_dracut_cmdline_file_parse(&params, path)) {
		ni_dracut_cmdline_apply(&params, &conf.netdevs);
		/*ni_cmdlineconfig_parse_cmdline_var
		ni_compat_generate_interfaces(array, &conf, FALSE, FALSE);*/
		return TRUE;
	}

	return FALSE;
}

/**
 * FIXME: this is a copy from __ni_suse_read_default_hostname
 * in compat-suse.c. Find a generic way of defining this function
 */
/** get default hostname from the system */
const char *
ni_compat_read_default_hostname(const char *root, char **hostname)
{
	const char *filenames[] = {
		"/etc/hostname",
		"/etc/HOSTNAME",
		NULL
	}, **name;
	char filename[PATH_MAX];
	char buff[256] = {'\0'};
	FILE *input;

	if (!hostname)
		return NULL;
	ni_string_free(hostname);

	for (name = filenames; name && !ni_string_empty(*name); name++) {
		snprintf(filename, sizeof(filename), "%s%s", root, *name);

		if (!ni_isreg(filename))
			continue;

		if (!(input = ni_file_open(filename, "r", 0600)))
			continue;

		if (fgets(buff, sizeof(buff)-1, input)) {
			buff[strcspn(buff, " \t\r\n")] = '\0';

			if (ni_check_domain_name(buff, strlen(buff), 0))
				ni_string_dup(hostname, buff);
		}
		fclose(input);
		break;
	}
	return *hostname;
}