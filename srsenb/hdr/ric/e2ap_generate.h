#ifndef RIC_E2AP_GENERATE_H
#define RIC_E2AP_GENERATE_H

#include "srsenb/hdr/ric/e2ap.h"
#include "E2AP_E2AP-PDU.h"

namespace ric {

class agent;

namespace e2ap {

int generate_e2_setup_request(
  ric::agent *agent,uint8_t **buffer,ssize_t *len);
int generate_ric_subscription_response(
  ric::agent *agent,ric::subscription_t *rs,uint8_t **buffer,ssize_t *len);
int generate_ric_subscription_failure(
  ric::agent *agent,ric::subscription_t *rs,uint8_t **buffer,ssize_t *len);
int generate_ric_subscription_delete_response(
  ric::agent *agent,long request_id,long instance_id,
  ric::ran_function_id_t function_id,uint8_t **buffer,ssize_t *len);
int generate_ric_subscription_delete_failure(
  ric::agent *agent,long request_id,long instance_id,
  ric::ran_function_id_t function_id,long cause,long cause_detail,
  uint8_t **buffer,ssize_t *len);
int generate_ric_service_update(
  ric::agent *agent,uint8_t **buffer,ssize_t *len);
int generate_reset_response(
  ric::agent *agent,uint8_t **buffer,ssize_t *len);

}
}
#endif
