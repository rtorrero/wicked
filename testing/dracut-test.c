#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>

#include <wicked/types.h>
#include <wicked/util.h>

#include "buffer.h"

#if 0
#include "client/dracut/cmdline.c"
#endif

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

#if 0
static ni_bool_t
ni_dracut_cmdline_line_parse(ni_string_array_t *params, ni_stringbuf_t *line)
{
	ni_stringbuf_t param = NI_STRINGBUF_INIT_DYNAMIC;
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
		ni_string_array_append(params, param.string);
		ni_stringbuf_clear(&param);
	}
	ni_stringbuf_destroy(&param);

	return ret != -1;
}
#endif

static ni_bool_t
ni_dracut_cmdline_line_parse_va(ni_var_array_t *params, ni_stringbuf_t *line)
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

#if 0
static ni_bool_t
ni_dracut_cmdline_file_parse(ni_string_array_t *params, const char *filename)
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
#endif

static ni_bool_t
ni_dracut_cmdline_file_parse_va(ni_var_array_t *params, const char *filename)
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
			ni_dracut_cmdline_line_parse_va(params, &line);
			ni_stringbuf_clear(&line);
		}
	}

	/* EOF while reading line with missing EOL termination */
	if (line.len) {
		ni_dracut_cmdline_line_parse_va(params, &line);
		ni_stringbuf_clear(&line);
	}

	ni_stringbuf_destroy(&line);
	fclose(file);
	return TRUE;
}

ni_bool_t
ni_dracut_is_same_key(const ni_var_t *var1, const ni_var_t *var2)
{
	return (strcmp(var1->name, var2->name) == 0);
}

unsigned int
ni_dracut_cmdline_extract_param()
{

}

static ni_bool_t
ni_dracut_cmdline_parse(const ni_var_array_t *params)
{
	unsigned int i, pos;
	const char *valid_params[] = {
		"ifname",
		"vlan",
		"bond",
		"bridge",
		"ip",
		NULL
	};

	const char **ptr;

	if (!params)
		return FALSE;

	// Extract all known params
	for (ptr = valid_params; *ptr; ++ptr) {
		const ni_var_t var = { .name = *ptr, .value = NULL };
		//pos = ni_var_array_find(params, 0, &(ni_var_t) {*ptr, ""}, &ni_dracut_is_same_key, NULL);
		for (pos = 0; (pos = ni_var_array_find(params, pos, &var, &ni_dracut_is_same_key, NULL)) != -1U; ++ptr) {
			printf("%s is %s \n", *ptr, params->data[pos].value);
			ni_var_array_remove_at(params, pos);
			pos = ni_var_array_find(params, 0, &(ni_var_t) {*ptr, ""}, &ni_dracut_is_same_key, NULL);
		}
		/* while (pos != -1U) {
			printf("%s is %s \n", *ptr, params->data[pos].value);
			ni_var_array_remove_at(params, pos);
			pos = ni_var_array_find(params, 0, &(ni_var_t) {*ptr, ""}, &ni_dracut_is_same_key, NULL);
		}*/
	}


	// Extract all ifname params
	// pos = ni_var_array_find(params, 0, &(ni_var_t) {"ifname", ""}, &ni_dracut_is_same_key, NULL);
	// while (pos != -1U) {
	// 	printf("ifname is %s \n", params->data[pos].value);
	// 	ni_var_array_remove_at(params, pos);
	// 	pos = ni_var_array_find(params, 0, &(ni_var_t) {"ifname", ""}, &ni_dracut_is_same_key, NULL);
	// }

	// Extract all vlan
	// Extract all bond
	// Extract all bridge


	// Extract all ip params
	// pos = ni_var_array_find(params, 0, &(ni_var_t) {"ip", ""}, &ni_dracut_is_same_key, NULL);
	// while (pos != -1U) {
	// 	printf("ip is %s \n", params->data[pos].value);
	// 	ni_var_array_remove_at(params, pos);
	// 	pos = ni_var_array_find(params, 0, &(ni_var_t) {"ip", ""}, &ni_dracut_is_same_key, NULL);
	// }

	return TRUE;
}

int
main(int argc, char *argv[])
{
	//ni_string_array_t params = NI_STRING_ARRAY_INIT;
	ni_var_array_t params = NI_VAR_ARRAY_INIT;
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	const char *directory = "dracut";
	unsigned int i;

	ni_scandir(directory, "*.conf", &files);
	for (i = 0; i < files.count; ++i) {
		char *filename = NULL;

		ni_string_printf(&filename, "%s/%s", directory, files.data[i]);
		ni_dracut_cmdline_file_parse_va(&params, filename);
		ni_string_free(&filename);
	}
	ni_string_array_destroy(&files);

	// Add additional params passed through arguments
	/* for (i = 1; i < (unsigned int)argc && argv[i]; ++i) {
		//ni_string_array_append(&params, argv[i]);
		ni_var_array_append(&params, argv[i]); //Missing third param
	}*/

	ni_dracut_cmdline_parse(&params);
	//ni_string_array_destroy(&params);
	ni_var_array_destroy(&params);
	return 0;
}
