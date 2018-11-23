#include <errno.h>
#include <stdint.h>

#include <unirec/unirec.h>

#include "bloom.h"
#include "bloom_history.h"
#include "bloom_history_config.h"


void bloom_history_config_init(struct bloom_history_config* config)
{
   config->size = 0;
   config->id = NULL;
   config->ip_prefix_length = NULL;
   config->ip_prefix = NULL;
   config->api_url = NULL;
   config->bloom_entries = NULL;
   config->bloom_fp_error_rate = NULL;
   config->bloom_list = NULL;
   config->bloom_list_size = 0;
}

int bloom_history_config_add_record(struct bloom_history_config* config, uint32_t id, ip_addr_t ip_prefix,
                           uint32_t ip_prefix_length, char** api_url, int32_t bloom_entries,
                           double bloom_fp_error_rate)
{
   size_t new_size = config->size + 1;

   config->id = realloc(config->id, sizeof(*(config->id)) * new_size);
   config->ip_prefix = realloc(config->ip_prefix, sizeof(*(config->ip_prefix)) * new_size);
   config->ip_prefix_length = realloc(config->ip_prefix_length, sizeof(*(config->ip_prefix_length)) * new_size);
   config->api_url = realloc(config->api_url, sizeof(*(config->api_url)) * new_size);
   config->bloom_entries = realloc(config->bloom_entries, sizeof(*(config->bloom_entries)) * new_size);
   config->bloom_fp_error_rate = realloc(config->bloom_fp_error_rate, sizeof(*(config->bloom_fp_error_rate)) * new_size);
   if (!config->id
       || !config->ip_prefix
       || !config->ip_prefix_length
       || !config->api_url
       || !config->bloom_entries
       || !config->bloom_fp_error_rate) {
      bloom_history_config_free(config);
      return -2;
   }
   config->size = new_size;

   config->id[new_size-1] = id;
   config->ip_prefix[new_size-1] = ip_prefix;
   config->ip_prefix_length[new_size-1] = ip_prefix_length;
   config->api_url[new_size-1] = *api_url;
   *api_url = NULL;
   config->bloom_entries[new_size-1] = bloom_entries;
   config->bloom_fp_error_rate[new_size-1] = bloom_fp_error_rate;

   return 0;
}

void bloom_history_config_free(struct bloom_history_config* config)
{
   if (config->id) {
      free(config->id);
      config->id = NULL;
   }
   if (config->ip_prefix_length) {
      free(config->ip_prefix_length);
      config->ip_prefix_length = NULL;
   }
   if (config->ip_prefix) {
      free(config->ip_prefix);
      config->ip_prefix = NULL;
   }
   if (config->api_url) {
      for (size_t i = 0; i < config->size; i++) {
         if (config->api_url[i]) {
            free(config->api_url[i]);
            config->api_url[i] = 0;
         }
      }
      free(config->api_url);
      config->api_url = NULL;
   }
   if (config->bloom_entries) {
      free(config->bloom_entries);
      config->bloom_entries = NULL;
   }
   if (config->bloom_fp_error_rate) {
      free(config->bloom_fp_error_rate);
      config->bloom_fp_error_rate = NULL;
   }
   if (config->bloom_list) {
      for (size_t i = 0; i < config->bloom_list_size; i++) {
         if (config->bloom_list[i]) {
            bloom_free(config->bloom_list[i]);
            free(config->bloom_list[i]);
            config->bloom_list[i] = 0;
         }
      }
      free(config->bloom_list);
      config->bloom_list = NULL;
   }

   config->size = 0;
   config->bloom_list_size = 0;
}

int bloom_history_parse_ip_prefix(char* ip_prefix, ip_addr_t* addr, uint32_t* prefix_length)
{
   long prefix_length_l;
   char *prefix_slash = strchr(ip_prefix, '/');

   if (prefix_slash == NULL) {
      return -1;
   }
   *prefix_slash = '\0';

   if (!ip_from_str(ip_prefix, addr)) {
      return -1;
   }

   prefix_length_l = strtol(prefix_slash + 1, NULL, 10);
   if (errno != 0) {
      return -1;
   }
   *prefix_length = prefix_length_l;
   if (*prefix_length != prefix_length_l) {
      return -1;
   }

   return 0;
}

int bloom_history_parse_config(const char* config_file, struct bloom_history_config *config)
{
   int error = 0;
   FILE * fp;
   char * line = NULL;
   size_t len = 0;
   uint32_t line_no = 1;
   ssize_t read;

   uint32_t id;
   char* ip_prefix_c = NULL;
   ip_addr_t ip_prefix;
   uint32_t ip_prefix_length;
   char* api_url = NULL;
   int32_t bloom_entries;
   double bloom_fp_error_rate;
   size_t max_id = 0;

   fp = fopen(config_file, "r");
   if (fp == NULL) {
      fprintf(stderr, "Error: %s\n", strerror(errno));
      return -1;
   }
   bloom_history_config_init(config);

   while(1) {
      read = getline(&line, &len, fp);
      debug_print("getline read %ld, errno %d\n", read, errno);
      if (errno != 0) {
         perror("Error reading config file");
         error = -1;
         goto cleanup;
      }
      if (read == -1) { // EOF
         break;
      }

      int scanned_fields = sscanf(line, "%u %ms %ms %d %lf", &id, &ip_prefix_c, &api_url, &bloom_entries, &bloom_fp_error_rate);
      debug_print("sscanf scanned_fields %d\n", scanned_fields);
      if (scanned_fields != 5) {
         error = line_no;
         goto cleanup;
      }

      error = bloom_history_parse_ip_prefix(ip_prefix_c, &ip_prefix, &ip_prefix_length);
      debug_print("bloom_history_parse_ip_prefix ret %d\n", error);
      if (error) {
         goto cleanup;
      }
      // api_url is "moved"
      error = bloom_history_config_add_record(config, id, ip_prefix, ip_prefix_length, &api_url, bloom_entries, bloom_fp_error_rate);
      debug_print("bloom_history_config_add_record ret %d\n", error);
      if (error) {
         goto cleanup;
      }
      if (id > max_id) {
         max_id = id;
      }

      free(ip_prefix_c);
      ip_prefix_c = NULL;
      line_no++;
   }

   // Allocate bloom filters on the right places
   config->bloom_list_size = max_id + 1;
   config->bloom_list = calloc(config->bloom_list_size, sizeof(*(config->bloom_list)));
   if (!config->bloom_list) {
      error = -42;
      goto cleanup;
   }
   for (size_t i = 0; i < config->size; i++) {
      uint32_t id = config->id[i];
      config->bloom_list[id] = calloc(1, sizeof(struct bloom));
      if (!config->bloom_list[id]) {
         error = -43;
         goto cleanup;
      }
      if (bloom_init(config->bloom_list[id], config->bloom_entries[i], config->bloom_fp_error_rate[i])) {
         error = -44;
         goto cleanup;
      }
   }

cleanup:
   if (line) {
      free(line);
   }
   if (ip_prefix_c) {
      free(ip_prefix_c);
   }
   if (api_url) {
      free(api_url);
   }
   fclose(fp);

   return error;
}
