#if !defined(_LIBCLAMAV_WWW_H)
#define _LIBCLAMAV_WWW_H

int connect_host(const char *host, const char *port);
size_t encoded_size(const char *postdata);
char *encode_data(const char *postdata);
void submit_post(const char *host, const char *port, const char *url, const char *postdata);

#endif
