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
#include <net/if_arp.h>

#include <wicked/util.h>
#include <wicked/ipv4.h>
#include <wicked/xml.h>
#include <wicked/netinfo.h>
#include <wicked/types.h>
#include <wicked/bridge.h>
#include <wicked/vlan.h>

#include "cmdline.h"
#include "client/wicked-client.h"
#include "buffer.h"

static const ni_intmap_t        dracut_params[] = {
	{ "ifname",             NI_DRACUT_PARAM_IFNAME  },
	{ "bridge",             NI_DRACUT_PARAM_BRIDGE  },
	{ "bond",               NI_DRACUT_PARAM_BOND    },
	{ "team", 		NI_DRACUT_PARAM_TEAM	},
	{ "vlan",               NI_DRACUT_PARAM_VLAN    },
	{ "ip",			NI_DRACUT_PARAM_IP	},
	{ NULL,                 -1U                     },
};

static const ni_intmap_t	bootprotos[] = {
	{ "off",	0	},
	{ "none",	1	},
	{ "dhcp",	2	},
	{ "on",		3	},
	{ "any",	4	},
	{ "dhcp6",	5	},
	{ "auto6",	6	},
	{ "ibft",	7	},
	{ NULL,		-1U	}
};

static inline char *
token_peek(char *ptr, char sep)
{
	return ptr ? strchr(ptr, sep) : NULL;
}

static inline char *
token_next(char *ptr, char sep)
{
	char *end;

	if ((end = token_peek(ptr, sep)))
		*end++ = '\0';

	return end;
}

const char *
ni_dracut_param_name(unsigned int *param)
{
        return ni_format_uint_mapped(*param, dracut_params);
}

static ni_bool_t
ni_dracut_cmdline_add_bootproto_dhcp(ni_compat_netdev_t *nd, char *val)
{
        ni_ipv4_devinfo_t *ipv4;

        ipv4 = ni_netdev_get_ipv4(nd->dev);
        ni_tristate_set(&ipv4->conf.enabled, TRUE);
        ni_tristate_set(&ipv4->conf.arp_verify, TRUE);

        nd->dhcp4.enabled = TRUE;
        ni_addrconf_update_set(&nd->dhcp4.update, NI_ADDRCONF_UPDATE_HOSTNAME, TRUE);
        ni_addrconf_update_set(&nd->dhcp4.update, NI_ADDRCONF_UPDATE_SMB, TRUE);

        //FIXME: read default as compat-suse.c does?
        nd->dhcp4.defer_timeout = 15;

        //ni_compat_read_default_hostname("", &__ni_suse_default_hostname);
        //ni_string_dup(&nd->dhcp4.hostname, __ni_suse_default_hostname);

        return TRUE;
}

static ni_bool_t
ni_dracut_cmdline_parse_bootproto(ni_compat_netdev_t *nd, char *val)
{
	unsigned int bootproto_type;

	if (ni_parse_uint_mapped(val, bootprotos, &bootproto_type) < 0)
		return FALSE;

	switch (bootproto_type) {
	case NI_DRACUT_BOOTPROTO_OFF:
	case NI_DRACUT_BOOTPROTO_NONE:
		ni_warn("Nothing to do here, bootproto is off/none\n");
		break;

	case NI_DRACUT_BOOTPROTO_DHCP:
		return ni_dracut_cmdline_add_bootproto_dhcp(nd, val);
		break;

	case NI_DRACUT_BOOTPROTO_ON:
	case NI_DRACUT_BOOTPROTO_ANY:
	case NI_DRACUT_BOOTPROTO_DHCP6:
	case NI_DRACUT_BOOTPROTO_AUTO6:
	case NI_DRACUT_BOOTPROTO_IBFT:
		ni_warn("Bootproto not implemented yet!\n");
		break;
	default:
		ni_warn("Bootproto unsupported!\n");
		break;
	}

	return FALSE;
}

/**
 * Adds a new compat_netdev_t to the array using
 * ifname as name or if it exists, adds the hwaddr/mtu to it
 */
static ni_compat_netdev_t *
ni_dracut_cmdline_add_netdev(ni_compat_netdev_array_t *nda, const char *ifname, const ni_hwaddr_t *hwaddr, const unsigned int *mtu, const int iftype)
{
	ni_compat_netdev_t *nd;

	nd = ni_compat_netdev_by_name(nda, ifname);

	/* We only apply the iftype if it hasn't been applied before
	   (to avoid overwriting netdevs created by bridge=..., vlan=... etc) */
	if (nd && (nd->dev->link.type == NI_IFTYPE_UNKNOWN))
		nd->dev->link.type = iftype;

	if (!nd) {
		nd = ni_compat_netdev_new(ifname);

		/* Assume default NI_IFTYPE_ETHERNET for newly created netdevs */
		nd->dev->link.type = iftype == NI_IFTYPE_UNKNOWN ?
			NI_IFTYPE_ETHERNET : iftype;
	}

	if (ifname && nd && hwaddr) {
		memcpy(nd->dev->link.hwaddr.data, hwaddr->data, hwaddr->len);
		nd->dev->link.hwaddr.len = hwaddr->len;
		nd->dev->link.hwaddr.type = hwaddr->type;
	}

	if (mtu) {
		nd->dev->link.mtu = *mtu;
	}

	ni_compat_netdev_array_append(nda, nd);

	return nd;
}

static ni_compat_netdev_t *
ni_dracut_cmdline_add_bridge(ni_compat_netdev_array_t *nda, const char *brname, char *ports)
{
	ni_bridge_t *bridge;
	ni_compat_netdev_t *nd;
	char *names = ports;
	char *next;

	nd = ni_dracut_cmdline_add_netdev(nda, brname, NULL, NULL, NI_IFTYPE_BRIDGE);
	nd->dev->link.type = NI_IFTYPE_BRIDGE;
	bridge = ni_netdev_get_bridge(nd->dev);

	for (next = token_peek(names, ','); next; names = next, next = token_peek(names, ',')) {
		++next;
		token_next(names, ',');
		if (!ni_netdev_name_is_valid(names)) {
			ni_warn("rejecting suspect port name '%s'", names);
			continue;
		}
		ni_bridge_port_new(bridge, names, 0);
	}
	ni_bridge_port_new(bridge, names, 0);

	return nd;
}

static ni_compat_netdev_t *
ni_dracut_cmdline_add_vlan(ni_compat_netdev_array_t *nda, const char *vlanname, const char *etherdev)
{
	char *vlantag;
	ni_vlan_t *vlan;
	ni_compat_netdev_t *nd;
	unsigned int tag = 0;
	size_t len;

	if (vlanname && !ni_netdev_name_is_valid(vlanname)) {
		ni_error("Rejecting suspect interface name: %s", vlanname);
		return FALSE;
	}

	nd = ni_dracut_cmdline_add_netdev(nda, vlanname, NULL, NULL, NI_IFTYPE_VLAN);
	nd->dev->link.type = NI_IFTYPE_VLAN;
	vlan = ni_netdev_get_vlan(nd->dev);

	if (!strcmp(vlanname, etherdev)) {
		ni_error("ifcfg-%s: ETHERDEVICE=\"%s\" self-reference",
			vlanname, etherdev);
		return FALSE;
	}

	// FIXME: use token_peek and token_next here?
	if ((vlantag = strrchr(vlanname, '.')) != NULL) {
		/* name.<TAG> */
		++vlantag;
	} else {
		/* name<TAG> */
		len = strlen(vlanname);
		vlantag = &vlanname[len];
		while(len > 0 && isdigit((unsigned char)vlantag[-1]))
			vlantag--;
	}

	if (ni_parse_uint(vlantag, &tag, 10) < 0) {
		ni_error("ifcfg-%s: Cannot parse vlan-tag from interface name",
			nd->dev->name);
		return FALSE;
	}
	vlan->protocol = NI_VLAN_PROTOCOL_8021Q;
	vlan->tag = tag;

	// Add the name
	nd->dev->name = xstrdup(vlanname);

	return nd;
}

/**
 * ip={dhcp|on|any|dhcp6|auto6|either6} syntax variant
 */
static ni_bool_t
parse_ip1(ni_compat_netdev_array_t *nda, char *val)
{
	unsigned int bootproto;
	ni_compat_netdev_t *compat;

	if (ni_parse_uint_mapped(val, bootprotos, &bootproto))
			return FALSE;

	compat = ni_dracut_cmdline_add_netdev(nda, NULL, NULL, NULL, NI_IFTYPE_UNKNOWN);

	return ni_dracut_cmdline_parse_bootproto(compat, val);
}

/**
 * ip=<interface>:{dhcp|on|any|dhcp6|auto6}[:[<mtu>][:<macaddr>]] syntax variant
 */
static ni_bool_t
parse_ip2(ni_compat_netdev_array_t *nda, char *val, const char *ifname)
{
        char *mac, *mtu;
        ni_hwaddr_t lladdr;
        unsigned int mtu_u32, bootproto;
	ni_compat_netdev_t *compat;

        if (!ni_netdev_name_is_valid(ifname))
                return FALSE;

        if ((mac = token_next(val, ':'))) {

                if (ni_string_len(mac) > ni_link_address_length(ARPHRD_ETHER)) {
                        mtu = mac;

                        if (!(mac = token_next(mtu, ':')))
                                return FALSE;

                        if (ni_parse_uint(mtu, &mtu_u32, 10))
                                return FALSE;

                        if (ni_link_address_parse(&lladdr, ARPHRD_ETHER, mac))
                                return FALSE;
                } else {
                        if (ni_link_address_parse(&lladdr, ARPHRD_ETHER, mac))
                                return FALSE;
                }
		compat = ni_dracut_cmdline_add_netdev(nda, ifname, &lladdr, &mtu_u32, NI_IFTYPE_UNKNOWN);
        } else {
		if (ni_parse_uint_mapped(val, bootprotos, &bootproto))
			return FALSE;

		compat = ni_dracut_cmdline_add_netdev(nda, ifname, NULL, NULL, NI_IFTYPE_UNKNOWN);
        }

	return ni_dracut_cmdline_parse_bootproto(compat, val);
}

/**
 * ip=<client-IP>:[<peer>]:<gateway-IP>:<netmask>:<client_hostname>:<interface>:{none|off|dhcp|on|any|dhcp6|auto6|ibft}[:[<mtu>][:<macaddr>]]
 */
static ni_bool_t
parse_ip3(ni_compat_netdev_array_t *nda, char *val, const char *client_ip)
{
	ni_sockaddr_t addr;

	if (ni_sockaddr_parse(&addr, client_ip, AF_UNSPEC))
		return FALSE;

	// ni_var_array_set(params, "client-ip", ni_sockaddr_print(&addr));
	// ni_var_array_set(params, "TODO", val);
	return TRUE;
}


/**
 * Guess what IP param syntax variant we have to parse and call the
 * appropriate function.
 */
ni_bool_t
ni_dracut_cmdline_parse_opt_ip(ni_compat_netdev_array_t *nd, ni_var_t *param)
{
	char *end, *beg;

	if (ni_string_empty(param->value))
		return FALSE;

	if ((beg = token_peek(param->value, '['))) {
		if (!(end = token_next(param->value, ']')))
			return FALSE;
		if (!(end = token_next(end, ':')))
			return FALSE;

		return parse_ip3(nd, end, beg + 1);
	} else
	if (isdigit((unsigned int)*param->value)) {
		if (!(end = token_next(param->value, ':')))
			return FALSE;

		return parse_ip3(nd, end, param->value);
	} else
	if ((end = token_next(param->value, ':'))) {
		return parse_ip2(nd, end, param->value);
	} else {
		return parse_ip1(nd, param->value);
	}
	return TRUE;
}

ni_bool_t
ni_dracut_cmdline_parse_opt_bond(ni_compat_netdev_array_t *nd, ni_var_t *param)
{

}

ni_bool_t
ni_dracut_cmdline_parse_opt_team()
{
	return TRUE;
}

ni_bool_t
ni_dracut_parse_opt_team()
{
	return TRUE;
}

ni_bool_t
ni_dracut_cmdline_parse_opt_bridge(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *end, *beg;

	if (ni_string_empty(param->value))
		return FALSE;

	beg = param->value;

	if (!(end = token_next(param->value, ':')))
		return FALSE;

	ni_dracut_cmdline_add_bridge(nda, beg, end);

	return TRUE;
}

ni_bool_t
ni_dracut_cmdline_parse_opt_ifname()
{
	return TRUE;
}

ni_bool_t
ni_dracut_cmdline_parse_opt_vlan(ni_compat_netdev_array_t *nda, ni_var_t *param)
{
	char *end, *beg;

	if (ni_string_empty(param->value))
		return FALSE;

	beg = param->value;

	if (!(end = token_next(param->value, ':')))
		return FALSE;

	ni_dracut_cmdline_add_vlan(nda, end, beg);
	return TRUE;
}


/**
 * Identify what function needs to be called to handle the supplied param
 **/
ni_bool_t
ni_dracut_cmdline_call_param_handler(ni_var_t *var, ni_compat_netdev_array_t *nd)
{
	unsigned int param_type;

	if (ni_parse_uint_mapped(var->name, dracut_params, &param_type) < 0)
		return FALSE;

	switch (param_type) {
		case NI_DRACUT_PARAM_IP:
			ni_dracut_cmdline_parse_opt_ip(nd, var);
			break;
		case NI_DRACUT_PARAM_BOND:
                        ni_dracut_cmdline_parse_opt_bond(nd, var);
			break;
		case NI_DRACUT_PARAM_BRIDGE:
                        ni_dracut_cmdline_parse_opt_bridge(nd, var);
			break;
		case NI_DRACUT_PARAM_TEAM:
                        ni_dracut_cmdline_parse_opt_team(nd, var);
			break;
		case NI_DRACUT_PARAM_IFNAME:
                        ni_dracut_cmdline_parse_opt_ifname(nd, var);
			break;
		case NI_DRACUT_PARAM_VLAN:
                        ni_dracut_cmdline_parse_opt_vlan(nd, var);
			break;

		default:
			ni_error("Dracut param %s not supported yet!\n", var->name);
			return FALSE;
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
		const ni_var_t match = { .name = pptr, .value = NULL };
		pos = 0;
		while ((pos = ni_var_array_find(params, pos, &match, &ni_var_name_equal, NULL)) != -1U) {
			printf("%s is %s \n", pptr, params->data[pos].value);
			ni_dracut_cmdline_call_param_handler(&params->data[pos], nd);
			++pos;
		}
	}

	return TRUE;
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
 * Take a stringbuf line and parse all the variables in the line
 * into a ni_var_array_t
 */
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
 * Read file into a stringbuf  and run line processing on it
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
	ni_compat_ifconfig_t conf;
	ni_compat_ifconfig_init(&conf, type);
	ni_var_array_t params = NI_VAR_ARRAY_INIT;

	if (ni_dracut_cmdline_file_parse(&params, path)) {
		ni_dracut_cmdline_apply(&params, &conf.netdevs);

		ni_compat_generate_interfaces(array, &conf, FALSE, FALSE);
		return TRUE;
	}

	return FALSE;
}