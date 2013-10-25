#if !defined(_LIBCLAMAV_STATS_H)
#define _LIBCLAMAV_STATS_H

void clamav_stats_add_sample(const char *virname, const unsigned char *md5, uint64_t size, cli_intel_sample_type_t type, void *cbdata);
void clamav_stats_submit(struct cl_engine *engine, void *cbdata);
void clamav_stats_flush(struct cl_engine *engine, void *cbdata);

#endif
