#include <errno.h>
#include <stdint.h>

#include <unirec/unirec.h>

#include "prefix_tags.h"
#include "prefix_tags_config.h"


void tags_config_init(struct tags_config* config) {
   config->size = 0;
   config->id = NULL;
   config->ip_prefix_length = NULL;
   config->ip_prefix = NULL;
}

int tags_config_add_record(struct tags_config* config, uint32_t id, ip_addr_t ip_prefix, uint32_t ip_prefix_length)
{
   size_t new_size = config->size + 1;

   config->id = realloc(config->id, sizeof(*(config->id)) * new_size);
   config->ip_prefix = realloc(config->ip_prefix, sizeof(*(config->ip_prefix)) * new_size);
   config->ip_prefix_length = realloc(config->ip_prefix_length, sizeof(*(config->ip_prefix_length)) * new_size);
   if (!config->id || !config->ip_prefix || !config->ip_prefix_length) {
      return -2;
   }
   config->size = new_size;


   config->id[new_size-1] = id;
   config->ip_prefix[new_size-1] = ip_prefix;
   config->ip_prefix_length[new_size-1] = ip_prefix_length;

   return 0;
}

void tags_config_free(struct tags_config* config)
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
   config->size = 0;
}

int tags_parse_ip_prefix(char* ip_prefix, ip_addr_t* addr, uint32_t* prefix_length)
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

int parse_config(const char* config_file, struct tags_config* config)
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

   fp = fopen(config_file, "r");
   if (fp == NULL) {
      fprintf(stderr, "Error: %s\n", strerror(errno));
      return -1;
   }

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

      int scanned_fields = sscanf(line, "%u %ms", &id, &ip_prefix_c);
      debug_print("sscanf scanned_fields %d\n", scanned_fields);
      if (scanned_fields != 2) {
         error = line_no;
         goto cleanup;
      }

      error = tags_parse_ip_prefix(ip_prefix_c, &ip_prefix, &ip_prefix_length);
      debug_print("tags_parse_ip_prefix ret %d\n", error);
      if (error) {
         goto cleanup;
      }
      error = tags_config_add_record(config, id, ip_prefix, ip_prefix_length);
      debug_print("tags_config_add_record ret %d\n", error);
      if (error) {
         goto cleanup;
      }

      free(ip_prefix_c);
      ip_prefix_c = NULL;
      line_no++;
   }

cleanup:
   if (line) {
      free(line);
   }
   if (ip_prefix_c) {
      free(ip_prefix_c);
   }
   fclose(fp);

   return error;
}
