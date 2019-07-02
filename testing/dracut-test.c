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

static ni_bool_t
ni_dracut_cmdline_from_file(ni_string_array_t *cmdlines, const char *filename)
{
	ni_stringbuf_t line = NI_STRINGBUF_INIT_DYNAMIC;
	char buf[BUFSIZ], eol;
	char *start = NULL;
	size_t len;
	FILE *file;

	if (!cmdlines || ni_string_empty(filename))
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
			start = ni_dracut_cmdline_cleanup_line(&line);
			ni_string_array_append(cmdlines, start);
			ni_stringbuf_clear(&line);
		}
	}

	ni_stringbuf_destroy(&line);
	fclose(file);
	return TRUE;
}


static ni_bool_t
ni_dracut_cmdline_parse_ip(const char *value)
{
	return TRUE;
}

static ni_bool_t
ni_dracut_cmdline_parse(const ni_string_array_t *cmdlines)
{
	unsigned int i;
	const char *value = NULL;
	if (!cmdlines)
		return FALSE;

	for (i = 0; i < cmdlines->count; ++i) {
		/*
		line = cleanup_mess(cmdlines->data[i]);
		*/
		printf(">>>%s<<<\n", cmdlines->data[i]);
		if (ni_string_startswith(cmdlines->data[i], "ip=")) {
			value = ni_string_strip_prefix(cmdlines->data[i], "ip=");
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
	ni_string_array_t cmdlines = NI_STRING_ARRAY_INIT;
	ni_string_array_t files = NI_STRING_ARRAY_INIT;
	const char *directory = "dracut";
	unsigned int i;

	ni_scandir(directory, "*.conf", &files);
	for (i = 0; i < files.count; ++i) {
		char *filename = NULL;

		ni_string_printf(&filename, "%s/%s", directory, files.data[i]);
		ni_dracut_cmdline_from_file(&cmdlines, filename);
		ni_string_free(&filename);
	}
	ni_string_array_destroy(&files);
	for (i = 1; i < (unsigned int)argc && argv[i]; ++i) {
		ni_string_array_append(&cmdlines, argv[i]);
	}

	ni_dracut_cmdline_parse(&cmdlines);
	ni_string_array_destroy(&cmdlines);
	return 0;
}
