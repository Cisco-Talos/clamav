#if !defined(_LIBCLAMAV_STATS_H)
#define _LIBCLAMAV_STATS_H

void clamav_stats_add_sample(const char *virname, const unsigned char *md5, uint64_t size, cli_intel_sample_type_t type, void *cbdata);
void clamav_stats_submit(struct cl_engine *engine, void *cbdata);
void clamav_stats_flush(struct cl_engine *engine, void *cbdata);
void clamav_stats_remove_sample(const char *virname, const unsigned char *md5, size_t size, cli_intel_sample_type_t type, void *cbdata);
void clamav_stats_decrement_count(const char *virname, const unsigned char *md5, size_t size, cli_intel_sample_type_t type, void *cbdata);
size_t clamav_stats_get_num(void *cbdata);
size_t clamav_stats_get_size(void *cbdata);
char *clamav_stats_get_hostid(void *cbdata);

#endif
