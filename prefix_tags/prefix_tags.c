/**
 * \file prefix_tags.c
 * \brief Tags unirec messages based on src_ip beloning to one of the configured prefixes
 * \author Filip Krestan <krestfi1@fit.cvut.cz>
 * \date 2018
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "fields.h"
#include "prefix_tags_config.h"


UR_FIELDS (
   ipaddr SRC_IP,
   ipaddr DST_IP,
   uint32 PREFIX_TAG
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
   BASIC("prefix_tags","This module adds PREFIX_TAG field to the output acording to configured ip prefixes.", 1, 0)

#define MODULE_PARAMS(PARAM) \
   PARAM('c', "config", "Configuration file.", required_argument, "string")

static int stop = 0;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

static const int INTERFACE_IN = 0;
static const int INTERFACE_OUT = 1;

int prefix_tags(struct tags_config* config) {
   int error = 0;
   int recv_error;
   int send_error;
   const void *data_in = NULL;
   uint16_t data_in_size;
   void *data_out = NULL;
   uint16_t data_out_size;
   ur_template_t *input_template = ur_create_input_template(INTERFACE_IN, "", NULL); // Gets updated on first use by TRAP_RECEIVE anyway
   ur_template_t *output_template = ur_create_output_template(INTERFACE_OUT, "", NULL);

   if (input_template == NULL || output_template == NULL) {
      error = -1;
      goto cleanup;
   }

   while (stop == 0) {
      recv_error = TRAP_RECEIVE(INTERFACE_IN, data_in, data_in_size, input_template);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(recv_error, continue, error = -2; goto cleanup)

      if (recv_error == TRAP_E_FORMAT_CHANGED) { // Copy format to output interface and add PREFIX_TAG
         if (ur_rec_varlen_size(input_template, data_in) != 0) {
            fprintf(stderr, "Error: Recieved input template with variable sized fields - this is currently not supported.\n");
            error = -2;
            goto cleanup;
         }
         // Reallocate output buffer
         if (data_out != NULL) {
            ur_free_record(data_out);
         }
         data_out = ur_create_record(output_template, 0); // Dynamic fields are currently not supported
         if (data_out == NULL) {
            error = -1;
            goto cleanup;
         }

         // Copy input template to output template
         char* input_template_str = ur_template_string(intput_template);
         if (input_template_str == NULL) {
            error = -1;
            goto cleanup;
         }
         ur_free_template(output_template);
         output_template = ur_create_output_template(INTERFACE_OUT, input_template_str, NULL);
         free(input_template_str);
         if (output_template == NULL) {
            error = -1;
            goto cleanup;
         }


         // TODO add TAG field
         ur_print_template(input_template);


         if (ur_set_output_template(INTERFACE_OUT, output_template) != UR_OK) {
            error = -6;
            goto cleanup;
         }
      }

      // data_out should have the right size since TRAP_E_FORMAT_CHANGED _had_ to be returned before getting here
      /* ur_copy_fields(output_template, data_out, input_template, data_in); */

      // TODO tag the thing
      /* send_error = trap_send(INTERFACE_OUT, data, data_size); */
      /* TRAP_DEFAULT_SEND_ERROR_HANDLING(send_error, continue, error = -3; break) */

      if (data_in_size <= 1) { // End of stream
         goto cleanup;
      }
   }

cleanup:
   if (data_out != NULL) {
      ur_free_record(data_out);
   }

   ur_free_template(input_template);
   ur_free_template(output_template);
   ur_finalize();

   return error;
}

int main(int argc, char **argv)
{
   int error = 0;
   signed char opt;

   struct tags_config config;

   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   tags_config_init(&config);

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'c':
         error = parse_config(optarg, &config);
         if (error != 0) {
            error = -1;
            goto cleanup;
         }
         break;
      }
   }

   error = prefix_tags(&config);

cleanup:
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   tags_config_free(&config);

   return error;
}
