
#include <sys/time.h>

#include "srslte/interfaces/enb_metrics_interface.h"
#include "srsenb/hdr/stack/rrc/rrc_metrics.h"
#include "srsenb/hdr/stack/upper/common_enb.h"
#include "srsenb/hdr/ric/e2ap.h"
#include "srsenb/hdr/ric/e2sm.h"
#include "srsenb/hdr/ric/agent.h"
#include "srsenb/hdr/ric/agent_asn1.h"
#include "srsenb/hdr/ric/e2sm_zylinium.h"
#include "srsenb/hdr/ric/e2ap_encode.h"
#include "srsenb/hdr/ric/e2ap_decode.h"
#include "srsenb/hdr/ric/e2ap_generate.h"

#include "E2AP_Cause.h"
#include "E2AP_RICindicationType.h"
#include "E2AP_RICcontrolStatus.h"
#include "E2SM_ZYLINIUM_RANfunction-Description.h"
#include "E2SM_ZYLINIUM_E2SM-Zylinium-ControlHeader.h"
#include "E2SM_ZYLINIUM_E2SM-Zylinium-ControlMessage.h"
#include "E2SM_ZYLINIUM_BlockedMask.h"
#include "E2SM_ZYLINIUM_E2SM-Zylinium-ControlOutcome.h"


namespace ric {

zylinium_model::zylinium_model(ric::agent *agent_) :
  service_model(agent_,"ORAN-E2SM-ZYLINIUM","1.3.6.1.4.1.1.1.2.101"),
  lock(PTHREAD_MUTEX_INITIALIZER)
{
}

int zylinium_model::init()
{
  ric::ran_function_t *func;
  E2SM_ZYLINIUM_RANfunction_Description_t *func_def;

  E2SM_INFO(agent,"zylinium: building function list\n");

  /* Create and encode our function list. */
  func = (ric::ran_function_t *)calloc(1,sizeof(*func));
  func->function_id = get_next_ran_function_id();
  func->model = this;
  func->revision = 0;
  func->name = "ORAN-E2SM-ZYLINIUM";
  func->description = "Zylinium API";

  func_def = (E2SM_ZYLINIUM_RANfunction_Description_t *) \
    calloc(1,sizeof(*func_def));

  func_def->ranFunction_Name.ranFunction_ShortName.buf = \
    (uint8_t *)strdup(func->name.c_str());
  func_def->ranFunction_Name.ranFunction_ShortName.size = \
    strlen(func->name.c_str());
  func_def->ranFunction_Name.ranFunction_E2SM_OID.buf = \
    (uint8_t *)strdup(func->model->oid.c_str());
  func_def->ranFunction_Name.ranFunction_E2SM_OID.size = \
    strlen(func->model->oid.c_str());
  func_def->ranFunction_Name.ranFunction_Description.buf = \
    (uint8_t *)strdup(func->description.c_str());
  func_def->ranFunction_Name.ranFunction_Description.size = \
    strlen(func->description.c_str());

  func->enc_definition_len = ric::e2ap::encode(
    &asn_DEF_E2SM_ZYLINIUM_RANfunction_Description,0,
    func_def,&func->enc_definition);
  if (func->enc_definition_len < 0) {
    E2SM_ERROR(agent,
      "failed to encode %s function %s!\n",
      name.c_str(),func->name.c_str());
    ASN_STRUCT_FREE_CONTENTS_ONLY(
      asn_DEF_E2SM_ZYLINIUM_RANfunction_Description,func_def);
    free(func_def);
    free(func);

    return -1;
  }

  func->enabled = 1;
  func->definition = func_def;

  functions.push_back(func);

  return 0;
}

void zylinium_model::stop()
{
  return;
}

int zylinium_model::handle_subscription_add(ric::subscription_t *sub)
{
  E2SM_ERROR(agent,"zylinium: subscriptions not supported\n");
  return -1;
}

int zylinium_model::handle_subscription_del(
  ric::subscription_t *sub,int force,long *cause,long *cause_detail)
{
  E2SM_ERROR(agent,"zylinium: subscriptions not supported\n");
  return -1;
}

void zylinium_model::handle_control(ric::control_t *rc)
{
  E2SM_ZYLINIUM_E2SM_Zylinium_ControlHeader_t ch;
  E2SM_ZYLINIUM_E2SM_Zylinium_ControlMessage_t cm;
  long cause = 0;
  long cause_detail = 0;
  uint8_t *buf;
  ssize_t len;
  int ret;

  E2SM_DEBUG(agent,"zylinium: handle_control\n");

  if (!rc->header_buf || rc->header_len < 1
      || !rc->message_buf || rc->message_len < 1) {
    E2SM_ERROR(agent,"e2sm zylinium missing control header or message\n");
    cause = 1;
    cause = 8;
    goto errout;
  }

  memset(&ch,0,sizeof(ch));
  if (ric::e2ap::decode(
	agent,&asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_ControlHeader,&ch,
	rc->header_buf,rc->header_len)) {
    E2SM_ERROR(agent,"failed to decode e2sm zylinium control header\n");
    cause = 1;
    cause_detail = 8;
    goto errout;
  }
  if (ch.present != E2SM_ZYLINIUM_E2SM_Zylinium_ControlHeader_PR_controlHeaderFormat1) {
    E2SM_ERROR(agent,"zylinium only supports control header Format1\n");
    cause = 1;
    cause_detail = 8;
    goto errout;
  }

  E2SM_DEBUG(agent,"control header:\n");
  E2SM_XER_PRINT(NULL,&asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_ControlHeader,&ch);

  memset(&cm,0,sizeof(cm));
  if (ric::e2ap::decode(
	agent,&asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_ControlMessage,&cm,
	rc->message_buf,rc->message_len)) {
    E2SM_ERROR(agent,"failed to decode e2sm zylinium control message\n");
    cause = 1;
    cause_detail = 8;
    goto errout;
  }
  if (cm.present != E2SM_ZYLINIUM_E2SM_Zylinium_ControlMessage_PR_controlMessageFormat1) {
    E2SM_ERROR(agent,"zylinium only supports control message Format1\n");
    cause = 1;
    cause_detail = 8;
    goto errout;
  }
  if (cm.choice.controlMessageFormat1.present < E2SM_ZYLINIUM_E2SM_Zylinium_ControlMessage_Format1_PR_maskConfigRequest
      || cm.choice.controlMessageFormat1.present > E2SM_ZYLINIUM_E2SM_Zylinium_ControlMessage_Format1_PR_maskStatusRequest) {
    E2SM_ERROR(agent,"unknown zylinium control message\n");
    cause = 1;
    cause_detail = 8;
    goto errout;
  }

  E2SM_DEBUG(agent,"control message:\n");
  E2SM_XER_PRINT(NULL,&asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_ControlMessage,&cm);

  ret = 0;
  switch (cm.choice.controlMessageFormat1.present) {
  case E2SM_ZYLINIUM_E2SM_Zylinium_ControlMessage_Format1_PR_maskConfigRequest:
    {
      E2SM_ZYLINIUM_MaskConfigRequest_t *req = \
	&cm.choice.controlMessageFormat1.choice.maskConfigRequest;
      std::string blocked_prbmask_str(
	(char *)req->blockedMask.blockedULPRBMask.buf,
	req->blockedMask.blockedULPRBMask.size);
      std::string blocked_rbgmask_str(
	(char *)req->blockedMask.blockedDLRBGMask.buf,
	req->blockedMask.blockedDLRBGMask.size);
      srsenb::rbgmask_t *blocked_rbgmask = \
	  srsenb::sched_utils::hex_str_to_rbgmask(blocked_rbgmask_str, agent->log.e2sm_ref);
      srsenb::prbmask_t *blocked_prbmask = \
	  srsenb::sched_utils::hex_str_to_prbmask(blocked_prbmask_str, agent->log.e2sm_ref);
      if (blocked_rbgmask && blocked_prbmask) {
        agent->enb_zylinium_interface->set_blocked_rbgmask(*blocked_rbgmask);
	agent->enb_zylinium_interface->set_blocked_prbmask(*blocked_prbmask);
	E2SM_DEBUG(agent,"configured blocked masks (dl %s, ul %s)\n",
		   blocked_rbgmask_str.c_str(),blocked_prbmask_str.c_str());
      }
      else {
	ret = 1;
	E2SM_ERROR(agent, "invalid blocked masks\n");
      }
    }
    break;
  case E2SM_ZYLINIUM_E2SM_Zylinium_ControlMessage_Format1_PR_maskStatusRequest:
  //  {
  //     E2SM_ZYLINIUM_NodeBStatusRequest_t *req = \
  // 	  &cm.choice.controlMessageFormat1.choice.nodeBStatusRequest;
  //     // Don't worry about nonexistent slice names.
  //     std::vector<std::string> slice_names;
  //     for (int i = 0; i < req->sliceNameList.list.count; ++i) {
  //       E2SM_ZYLINIUM_SliceName_t *sn = (E2SM_ZYLINIUM_SliceName_t *) \
  // 	  req->sliceNameList.list.array[i];
  // 	std::string slice_name((char *)sn->buf,sn->size);
  // 	slice_names.push_back(slice_name);
  //     }
  //     std::vector<slicer::slice_status_t> slice_statuses = \
  // 	agent->enb_slicer_interface->slice_status(slice_names);
      
  //     ret = 0;
  //     break;
  //   }
  default:
    E2SM_ERROR(agent,"unknown zylinium control message\n");
    ret = 1;
    cause = 1;
    cause_detail = 8;
  }

  if (ret) {
    E2SM_ERROR(agent,"error while handling zylinium control request (%d)\n",ret);
    cause = 1;
    cause_detail = 8;
    goto errout;
  }

  if (rc->request_ack == CONTROL_REQUEST_ACK) {
    E2SM_DEBUG(agent,
	       "building nodeb status report:\n");
    E2SM_ZYLINIUM_E2SM_Zylinium_ControlOutcome_t outcome;
    memset(&outcome,0,sizeof(outcome));
    outcome.present = E2SM_ZYLINIUM_E2SM_Zylinium_ControlOutcome_PR_controlOutcomeFormat1;
    outcome.choice.controlOutcomeFormat1.present = \
      E2SM_ZYLINIUM_E2SM_Zylinium_ControlOutcome_Format1_PR_maskStatusReport;
    // std::vector<slicer::slice_status_t> statuses = \
    // 	agent->enb_slicer_interface->slice_status(std::vector<std::string>());
    // fill_slice_status_report(
    //   &outcome.choice.controlOutcomeFormat1.choice.sliceStatusReport,
    //   statuses);
    E2SM_DEBUG(agent,"zylinium mask status report:\n");
    E2SM_XER_PRINT(NULL,&asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_ControlOutcome,&outcome);
    uint8_t *enc_outcome = NULL;
    ssize_t enc_outcome_len = ric::e2ap::encode(
      &asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_ControlOutcome,0,
      &outcome,&enc_outcome);
    if (enc_outcome_len < 0 || !enc_outcome) {
      E2SM_WARN(agent,
		"failed to encode zylinium mask status report!\n");
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(
      asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_ControlOutcome,&outcome);
    ret = ric::e2ap::generate_ric_control_acknowledge(
      agent,rc,E2AP_RICcontrolStatus_success,enc_outcome,enc_outcome_len,&buf,&len);
    if (enc_outcome)
      free(enc_outcome);
    if (ret) {
      E2AP_ERROR(agent,"failed to generate RICcontrolFailure\n");
    }
    else {
      agent->send_sctp_data(buf,len);
    }
  }

  delete rc;
  return;

 errout:
  ret = ric::e2ap::generate_ric_control_failure(
    agent,rc,cause,cause_detail,NULL,0,&buf,&len);
  if (ret) {
    E2AP_ERROR(agent,"failed to generate RICcontrolFailure\n");
  }
  else {
    agent->send_sctp_data(buf,len);
  }
  delete rc;
  return;
}

}
