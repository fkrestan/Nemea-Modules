#ifndef __BLOOM_HISTORY_CONFIG_H_
#define __BLOOM_HISTORY_CONFIG_H_
#define _GNU_SOURCE

#include <stdint.h>

#include <unirec/unirec.h>


/* 1 170.30.0.0/23 https://localhost:8081/ 2000000 0.01 */
struct bloom_history_config {
   size_t size;
   uint32_t* id;
   ip_addr_t* ip_prefix;
   uint32_t* ip_prefix_length;
   char** api_url;
   int32_t* bloom_entries;
   double* bloom_fp_error_rate;
};

void bloom_history_config_init(struct bloom_history_config* config);

int bloom_history_config_add_record(struct bloom_history_config* config, uint32_t id, ip_addr_t ip_prefix,
                           uint32_t ip_prefix_length, char** api_url, int32_t bloom_entries,
                           double bloom_fp_error_rate);

void bloom_history_config_free(struct bloom_history_config* config);

int bloom_history_parse_ip_prefix(char* ip_prefix, ip_addr_t* addr, uint32_t* prefix_length);

int bloom_history_parse_config(const char* config_file, struct bloom_history_config* config);


#endif // __BLOOM_HISTORY_CONFIG_H_
