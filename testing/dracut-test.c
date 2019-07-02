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

/** unquoute: this is taken from sysconfig.c,
 * find a place to put it
 */
static ni_bool_t
unquote(char *string)
{
	char quote_sign = 0;
	char *src, *dst, cc, lc = 0;
	ni_bool_t ret = TRUE;

	if (!string)
		return ret;

	ret = TRUE;
	src = dst = string;
	if (*string == '"' || *string == '\'') {
		quote_sign = *string;
		src++;
	}
	do {
		cc = *src;
		if (!cc) {
			ret = quote_sign && lc == quote_sign;
			break;
		}
		if (isspace(cc) && !quote_sign)
			break;
		if (cc == quote_sign)
			break;
		*dst = lc = cc;
		dst++;
		src++;
	} while (1);

	*dst = '\0';
	return ret;
}

/**
 * Return a pointer to the first non-whitespace char in the line
 */
static char *
ni_dracut_cmdline_cleanup_line(ni_stringbuf_t *line)
{
	char *start = line->string;
	int i;

	for (i = 0; i < (int)line->len; ++i) {
		if (isspace(*start))
			++start;
		else
			break;
	}


	return start;
}

/**
 * Takes a line and extracts to a ni_string_array all the variables
 */
static char *
ni_dracut_cmdline_from_line(ni_string_array_t *cmdline, const ni_string_array_t *lines)
{
	int i;
	char *sp;

	for (i = 0; i < lines->count; ++i) {
		sp = lines->data[i];
		printf("quote appears %d times\n", ni_string_count_char(lines->data[i], "\""));
		/*`while (*sp != '\n' && *sp != '\0') {

		}*/
	}
}

static ni_bool_t
ni_dracut_cmdline_from_file(ni_string_array_t *lines, const char *filename)
{
	ni_stringbuf_t line = NI_STRINGBUF_INIT_DYNAMIC;
	ni_string_array_t cmdline = NI_STRING_ARRAY_INIT;
	char buf[BUFSIZ], eol;
	char *start = NULL;
	size_t len;
	FILE *file;

	if (!lines || ni_string_empty(filename))
		return FALSE;

	if (!(file = fopen(filename, "r")))
		return FALSE;

	memset(&buf, 0, sizeof(buf));
	while (fgets(buf, sizeof(buf), file)) {
		len = strcspn(buf, "\r\n");
		eol = buf[len];
		buf[len] = '\0';

		if (len)
			ni_stringbuf_puts(&line, buf);
		if (eol) {
			//start = ni_dracut_cmdline_cleanup_line(&line);
			//ni_string_array_append(lines, start);

			// Alternative
			ni_stringbuf_trim_head(&line, " ");
			ni_string_array_append(lines, line.string);
			ni_dracut_cmdline_from_line(&cmdline, lines);
			ni_stringbuf_clear(&line);
		}
	}

	ni_stringbuf_destroy(&line);
	fclose(file);
	return TRUE;
}


static ni_bool_t
ni_dracut_cmdline_parse_ip(char *value)
{
	return TRUE;
}

static char *
ni_dracut_cmdline_cleanup(char *line) {
	unquote(line);
	return line;
}

static ni_bool_t
ni_dracut_cmdline_parse(const ni_string_array_t *lines)
{
	unsigned int i;
	const char *value = NULL, *line = NULL;
	if (!lines)
		return FALSE;

	for (i = 0; i < lines->count; ++i) {

		line = ni_dracut_cmdline_cleanup(lines->data[i]);

		printf(">>>%s<<<\n", lines->data[i]);
		if (ni_string_startswith(lines->data[i], "ip=")) {
			value = ni_string_strip_prefix("ip=", lines->data[i]);
			printf("ip line value: %s \n", value);
		}
		/*
		off = strcspn(line, "=");
		key = line;
		if (line[off])
			val = line + off;
		else
			val = NULL;
		key[off] = '\0';

		-> passe_key_value(&key, &val, line);

		{ .name = "ip", .func = ni_dracut_cmdline_parse_ip }
		if (ni_string_eq("ip", key)) {
			ni_dracut_cmdline_parse_ip();
		}
		*/
	}

	return TRUE;
}

int
main(int argc, char *argv[])
{
	ni_string_array_t lines = NI_STRING_ARRAY_INIT;
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	const char *directory = "dracut";
	unsigned int i;

	ni_scandir(directory, "*.conf", &files);
	for (i = 0; i < files.count; ++i) {
		char *filename = NULL;

		ni_string_printf(&filename, "%s/%s", directory, files.data[i]);
		ni_dracut_cmdline_from_file(&lines, filename);
		ni_string_free(&filename);
	}
	ni_string_array_destroy(&files);
	for (i = 1; i < (unsigned int)argc && argv[i]; ++i) {
		ni_string_array_append(&lines, argv[i]);
	}

	ni_dracut_cmdline_parse(&lines);
	ni_string_array_destroy(&lines);
	return 0;
}
