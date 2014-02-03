#if !defined(_LIBCLAMAV_WWW_H)
#define _LIBCLAMAV_WWW_H

int connect_host(const char *host, const char *port, uint32_t timeout, int useAsync);
size_t encoded_size(const char *postdata);
char *encode_data(const char *postdata);
void submit_post(const char *host, const char *port, const char *method, const char *url, const char *postdata, uint32_t timeout);

#endif
