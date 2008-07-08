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
		txtbuf->capacity = MAX(txtbuf->pos + len, txtbuf->capacity + 4096);
		d = cli_realloc(txtbuf->data, txtbuf->capacity);
		if(!d)
			return -1;
		txtbuf->data = d;
	}
	return 0;
}

static inline void textbuffer_append_len(struct text_buffer *txtbuf, const char *s, size_t len)
{
	textbuffer_ensure_capacity(txtbuf, len);
	memcpy(&txtbuf->data[txtbuf->pos], s, len);
	txtbuf->pos += len;
}


static inline void textbuffer_append(struct text_buffer *txtbuf, const char *s)
{
	size_t len = strlen(s);
	textbuffer_append_len(txtbuf, s, len);
}

static inline void textbuffer_putc(struct text_buffer *txtbuf, const char c)
{
	textbuffer_ensure_capacity(txtbuf, 1);
	txtbuf->data[txtbuf->pos++] = c;
}
#endif
