#pragma once

static const char *next_line(const char *s)
{
	while (*s && *s != '\n')
		++s;
	return *s == '\n' ? s + 1 : NULL;
}

static const char *starts_with(const char *s, const char *t)
{
	while (*t && *t++ == *s++)
		;
	return *t ? NULL : s;
}

static const char *parse_hex(const char *s, unsigned long *r)
{
	unsigned long v;
	char c;

	v = 0;
	while ((c = *s++)) {
		switch (c) {
		case 'A' ... 'F':
			v = v * 16 + (c - 'A') + 10;
			break;
		case 'a' ... 'f':
			v = v * 16 + (c - 'a') + 10;
			break;
		case '0' ... '9':
			v = v * 16 + (c - '0');
			break;
		default:
			goto out;
		}
	}

out:
	*r = v;
	return --s;
}
