/*
 *	wicked client configuration reading along their assosciated sub-types.
 *
 *	Copyright (C) 2010-2018 SUSE LINUX GmbH, Nuernberg, Germany.
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
 *		Olaf Kirch <okir@suse.de>
 *		Marius Tomaschewski <mt@suse.de>
 *		Pawel Wieczorkiewicz <pwieczorkiewicz@suse.de>
 *		Rubén Torrero Marijnissen <rtorreromarijnissen@suse.com>
 */
#ifndef WICKED_CLIENT_DRACUT_CMDLINE_H
#define WICKED_CLIENT_DRACUT_CMDLINE_H


/**
 * FIXME: it probably doesn't make much sense to expose the enums in the .h
 */
typedef enum ni_cmdlineconfig_dracut_params {
	NI_DRACUT_PARAM_IFNAME = 0U,
	NI_DRACUT_PARAM_BRIDGE,
	NI_DRACUT_PARAM_BOND,
	NI_DRACUT_PARAM_TEAM,
	NI_DRACUT_PARAM_VLAN,
	NI_DRACUT_PARAM_IP,
} ni_cmdlineconfig_dracut_params_t;

typedef enum ni_cmdlineconfig_dracut_bootprotos {
	NI_DRACUT_BOOTPROTO_OFF = 0U,
	NI_DRACUT_BOOTPROTO_NONE,
	NI_DRACUT_BOOTPROTO_DHCP,
	NI_DRACUT_BOOTPROTO_ON,
	NI_DRACUT_BOOTPROTO_ANY,
	NI_DRACUT_BOOTPROTO_DHCP6,
	NI_DRACUT_BOOTPROTO_AUTO6,
	NI_DRACUT_BOOTPROTO_IBFT,
} ni_cmdlineconfig_dracut_bootprotos_t;

extern ni_bool_t	ni_ifconfig_read_dracut_cmdline(xml_document_array_t *,
						const char *,
						const char *,
						const char *,
						ni_bool_t,
						ni_bool_t);

#endif /* WICKED_CLIENT_DRACUT_CMDLINE_H */