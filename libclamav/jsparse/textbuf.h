#ifndef TEXTBUF_H
#define TEXTBUF_H
struct text_buffer {
	char *data;
	size_t pos;
	size_t capacity;
};

static inline int textbuffer_ensure_capacity(struct text_buffer *txtbuf, size_t len)
{
	if (txtbuf->pos + len > txtbuf->capacity) {
		char *d;
		unsigned capacity = MAX(txtbuf->pos + len, txtbuf->capacity + 4096);
		d = cli_realloc(txtbuf->data, capacity);
		if(!d)
			return -1;
		txtbuf->capacity = capacity;
		txtbuf->data = d;
	}
	return 0;
}

static inline int textbuffer_append_len(struct text_buffer *txtbuf, const char *s, size_t len)
{
	if(textbuffer_ensure_capacity(txtbuf, len) == -1)
		return -1;
	memcpy(&txtbuf->data[txtbuf->pos], s, len);
	txtbuf->pos += len;
	return 0;
}


static inline int textbuffer_append(struct text_buffer *txtbuf, const char *s)
{
	size_t len = strlen(s);
	return textbuffer_append_len(txtbuf, s, len);
}

static inline int textbuffer_putc(struct text_buffer *txtbuf, const char c)
{
	if(textbuffer_ensure_capacity(txtbuf, 1) == -1)
		return -1;
	txtbuf->data[txtbuf->pos++] = c;
	return 0;
}
#endif
