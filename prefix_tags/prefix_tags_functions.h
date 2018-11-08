#ifndef __PREFIX_TAGS_FUNCTIONS_H_
#define __PREFIX_TAGS_FUNCTIONS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <unirec/unirec.h>


int update_output_format(ur_template_t *template_in, const void *data_in, ur_template_t **template_out, void **data_out);

int is_from_prefix(ip_addr_t *ip, ip_addr_t *protected_prefix, int32_t protected_prefix_length);

int is_from_configured_prefix(stuct tags_config *conig, const ip_addr_t *ip, uint32_t *prefix_tag);

#endif // __PREFIX_TAGS_FUNCTIONS_H_
