
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

#include "E2AP_RICactionType.h"
#include "E2AP_Cause.h"
#include "E2AP_RICindicationType.h"
#include "E2AP_RICcontrolStatus.h"
#include "E2SM_ZYLINIUM_RANfunction-Description.h"
#include "E2SM_ZYLINIUM_E2SM-Zylinium-IndicationHeader.h"
#include "E2SM_ZYLINIUM_E2SM-Zylinium-IndicationMessage.h"
#include "E2SM_ZYLINIUM_E2SM-Zylinium-ControlHeader.h"
#include "E2SM_ZYLINIUM_E2SM-Zylinium-ControlMessage.h"
#include "E2SM_ZYLINIUM_BlockedMask.h"
#include "E2SM_ZYLINIUM_E2SM-Zylinium-ControlOutcome.h"
#include "E2SM_ZYLINIUM_E2SM-Zylinium-EventTriggerDefinition.h"


namespace ric {

static void encode_blocked_mask(BlockedMask& m,E2SM_ZYLINIUM_BlockedMask *em)
{
  em->mask.size = strlen(m.mask_str.c_str());
  em->mask.buf = (uint8_t *)malloc(em->mask.size);
  memcpy(em->mask.buf,m.mask_str.c_str(),em->mask.size);
  em->start = m.start;
  em->end = m.end;
  em->id = m.id;
}

static void encode_mask_status_report(MaskStatus& masks, E2SM_ZYLINIUM_MaskStatusReport *maskStatusReport)
{
  encode_blocked_mask(masks.dl, &maskStatusReport->dlMask);
  encode_blocked_mask(masks.ul, &maskStatusReport->ulMask);

  maskStatusReport->dlDefault.size = strlen(masks.dl_def.mask_str.c_str());
  if (maskStatusReport->dlDefault.size > 0) {
    maskStatusReport->dlDefault.buf = (uint8_t *)malloc(maskStatusReport->dlDefault.size);
    memcpy(maskStatusReport->dlDefault.buf,masks.dl_def.mask_str.c_str(),maskStatusReport->dlDefault.size);
  }
  maskStatusReport->ulDefault.size = strlen(masks.ul_def.mask_str.c_str());
  if (maskStatusReport->ulDefault.size > 0) {
    maskStatusReport->ulDefault.buf = (uint8_t *)malloc(maskStatusReport->ulDefault.size);
    memcpy(maskStatusReport->ulDefault.buf,masks.ul_def.mask_str.c_str(),maskStatusReport->ulDefault.size);
  }

  for (auto it = masks.dl_sched.begin(); it != masks.dl_sched.end(); ++it) {
    E2SM_ZYLINIUM_BlockedMask_t *bm = (E2SM_ZYLINIUM_BlockedMask_t *)calloc(sizeof(*bm),1);
    encode_blocked_mask(*it,bm);
    ASN_SEQUENCE_ADD(&maskStatusReport->dlSched.list,bm);
  }

  for (auto it = masks.ul_sched.begin(); it != masks.ul_sched.end(); ++it) {
    E2SM_ZYLINIUM_BlockedMask_t *bm = (E2SM_ZYLINIUM_BlockedMask_t *)calloc(sizeof(*bm),1);
    encode_blocked_mask(*it,bm);
    ASN_SEQUENCE_ADD(&maskStatusReport->ulSched.list,bm);
  }
}

zylinium_model::zylinium_model(ric::agent *agent_) :
  service_model(agent_,"ORAN-E2SM-ZYLINIUM","1.3.6.1.4.1.1.1.2.101"),
  lock(PTHREAD_MUTEX_INITIALIZER),masks(),thread(0),running(false),
  cond(PTHREAD_COND_INITIALIZER),serial_number(1)
{
}

int zylinium_model::init()
{
  ric::ran_function_t *func;
  E2SM_ZYLINIUM_RANfunction_Description_t *func_def;

  pthread_mutex_lock(&lock);
  if (running) {
    pthread_mutex_unlock(&lock);
    E2SM_ERROR(agent,"zylinium: already initialized and running\n");
    return false;
  }

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

  running = true;
  if (pthread_create(&thread,NULL,zylinium_model::run,this) != 0) {
    running = false;
    pthread_mutex_unlock(&lock);
    return -1;
  }
  pthread_mutex_unlock(&lock);

  return 0;
}

void zylinium_model::stop()
{
  pthread_mutex_lock(&lock);
  running = false;
  subscriptions.clear();
  pthread_mutex_unlock(&lock);

  pthread_cond_signal(&cond);
  pthread_join(thread,NULL);

  return;
}

int zylinium_model::handle_subscription_add(ric::subscription_t *sub)
{
  E2SM_ZYLINIUM_E2SM_Zylinium_EventTriggerDefinition_t etdef;
  ric::action_t *action;
  bool any_actions_enabled = false;

  if (sub->event_trigger.size < 1 || sub->event_trigger.buf == NULL) {
    E2SM_ERROR(agent,"zylinium: no event trigger\n");
    return -1;
  }

  memset(&etdef,0,sizeof(etdef));
  if (ric::e2ap::decode(
	agent,&asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_EventTriggerDefinition,&etdef,
	sub->event_trigger.buf,sub->event_trigger.size)) {
    E2SM_ERROR(agent,"failed to decode e2sm zylinium event trigger definition\n");
    goto errout;
  }
  if (etdef.present != E2SM_ZYLINIUM_E2SM_Zylinium_EventTriggerDefinition_PR_ranEventDefinition) {
    E2SM_ERROR(agent,"zylinium: only supports the ranEventDefinition trigger\n");
    goto errout;
  }

  for (std::list<ric::action_t *>::iterator it = sub->actions.begin(); it != sub->actions.end(); ++it) {
    action = *it;
    if (action->type != E2AP_RICactionType_report) {
	E2SM_WARN(agent,"zylinium: invalid actionType %ld; not enabling this action\n",
		  action->type);
      continue;
    }
    action->enabled = true;
    any_actions_enabled = true;
  }
  if (!any_actions_enabled) {
    E2SM_ERROR(agent,"zylinium: no actions enabled; failing subscription\n");
    goto errout;
  }

  /* This is a valid subscription; add it. */
  pthread_mutex_lock(&lock);
  subscriptions.push_back(sub);

  pthread_mutex_unlock(&lock);

  return 0;

 errout:
  pthread_mutex_unlock(&lock);
  ASN_STRUCT_FREE_CONTENTS_ONLY(
    asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_EventTriggerDefinition,(&etdef));

  return -1;
}

int zylinium_model::handle_subscription_del(
  ric::subscription_t *sub,int force,long *cause,long *cause_detail)
{
  pthread_mutex_lock(&lock);

  subscriptions.remove(sub);

  pthread_mutex_unlock(&lock);

  return 0;
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
  MaskStatus masks_copy;

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

      srsenb::rbgmask_t def_rbgmask(25);
      std::string def_rbgmask_str((char *)req->dlDefault.buf,req->dlDefault.size);
      if (!srsenb::sched_utils::hex_str_to_rbgmask(def_rbgmask_str, def_rbgmask, agent->log.e2sm_ref)) {
	ret = 1;
	E2SM_ERROR(agent,"zylinium: invalid default dl prbmask\n");
	goto errout;
      }
      srsenb::prbmask_t def_prbmask(100);
      std::string def_prbmask_str((char *)req->ulDefault.buf,req->ulDefault.size);
      if (!srsenb::sched_utils::hex_str_to_prbmask(def_prbmask_str, def_prbmask, agent->log.e2sm_ref)) {
	ret = 1;
	E2SM_ERROR(agent,"zylinium: invalid default ul prbmask\n");
	goto errout;
      }

      std::list<DlBlockedMask> dl_sched;
      for (int i = 0; i < req->dlSched.list.count; ++i) {
	std::string rbgmask_str((char *)req->dlSched.list.array[i]->mask.buf,
				req->dlSched.list.array[i]->mask.size);
	srsenb::rbgmask_t rbgmask(25);
	if (!srsenb::sched_utils::hex_str_to_rbgmask(rbgmask_str, rbgmask, agent->log.e2sm_ref)) {
	  ret = 1;
	  E2SM_ERROR(agent,"zylinium: invalid dl rbgmask (slot %d)\n",i);
	  goto errout;
	}
	double start = req->dlSched.list.array[i]->start;
	double end = req->dlSched.list.array[i]->end;
	int id = req->dlSched.list.array[i]->id;
	dl_sched.push_back(DlBlockedMask(rbgmask, rbgmask_str, start, end, id));
      }

      std::list<UlBlockedMask> ul_sched;
      for (int i = 0; i < req->ulSched.list.count; ++i) {
	std::string prbmask_str((char *)req->ulSched.list.array[i]->mask.buf,
				req->ulSched.list.array[i]->mask.size);
	srsenb::prbmask_t prbmask(100);
	if (!srsenb::sched_utils::hex_str_to_prbmask(prbmask_str, prbmask, agent->log.e2sm_ref)) {
	  ret = 1;
	  E2SM_ERROR(agent,"zylinium: invalid ul prbmask (slot %d)\n",i);
	  goto errout;
	}
	double start = req->ulSched.list.array[i]->start;
	double end = req->ulSched.list.array[i]->end;
	int id = req->ulSched.list.array[i]->id;
	ul_sched.push_back(UlBlockedMask(prbmask, prbmask_str, start, end, id));
      }

      /* Update the live config and notify our handler thread to deploy. */
      pthread_mutex_lock(&lock);
      masks.dl_def = DlBlockedMask(def_rbgmask, def_rbgmask_str, 0, 0, 0);
      masks.ul_def = UlBlockedMask(def_prbmask, def_prbmask_str, 0, 0, 0);
      masks.dl_sched = dl_sched;
      masks.ul_sched = ul_sched;
      masks_copy = masks;
      pthread_mutex_unlock(&lock);

      pthread_cond_signal(&cond);
    }
    break;
  case E2SM_ZYLINIUM_E2SM_Zylinium_ControlMessage_Format1_PR_maskStatusRequest:
    {
      pthread_mutex_lock(&lock);
      masks_copy = masks;
      pthread_mutex_unlock(&lock);
    }
    break;
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
	       "zylinium: building mask status report:\n");
    E2SM_ZYLINIUM_E2SM_Zylinium_ControlOutcome_t outcome;
    memset(&outcome,0,sizeof(outcome));
    outcome.present = E2SM_ZYLINIUM_E2SM_Zylinium_ControlOutcome_PR_controlOutcomeFormat1;
    outcome.choice.controlOutcomeFormat1.present = \
      E2SM_ZYLINIUM_E2SM_Zylinium_ControlOutcome_Format1_PR_maskStatusReport;
    encode_mask_status_report(masks_copy, &outcome.choice.controlOutcomeFormat1.choice.maskStatusReport);

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
      E2AP_ERROR(agent,"failed to generate RICcontrolStatus\n");
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

void *zylinium_model::run(void *arg)
{
  zylinium_model *model = (zylinium_model *)arg;

  pthread_setname_np(pthread_self(),"ZYLINIUM");

  pthread_mutex_lock(&model->lock);
  while (model->running) {
    struct timeval now;
    gettimeofday(&now,NULL);
    double nowf = static_cast<double>(now.tv_sec) + now.tv_usec / 1000000.0f;

    double dl_next = 0.0f, ul_next = 0.0f;
    bool dl_set = false, ul_set = false;

    /*
     * Handle the DL first.
     */

    /*
     * Check the schedule.  Set the current mask to the first one in the
     * list if its start and end are both < nowf.  If that results in a
     * valid current mask (one with start < nowf and end <=0 or end > nowf),
     * push that one back on the front of the schedule.
     */
    double dl_next_start = 0.0f;
    if (!model->masks.dl_sched.empty()) {
      DlBlockedMask& top = model->masks.dl_sched.front();
      bool popped = false;
      /*
       * This is suboptimal, but we need to skip past masks whose
       * start/end are fully in the past; as well as move to the "newest"
       * start that has no end.  If we wind up with a top with no end, we
       * have to push_front it.
       */
      while (top.start < nowf && (top.end < nowf || model->masks.dl.end <= 0)) {
	/*
	 * Check if the current mask is still valid, and to not call down
	 * into the scheduler nor send an E2 indication if no change
	 * happened.  This will be true if its end is is 0, meaning don't
	 * change until the next mask in the schedule, and there is no new
	 * mask yet.
	 */
	if (model->masks.dl != top) {
	  E2SM_DEBUG(model->agent, "zylinium: setting dl mask (%s,%f,%f,%d)\n",
		     top.mask_str.c_str(), top.start, top.end, top.id);
	  model->masks.dl = top;
	  dl_set = true;
	}
	model->masks.dl_sched.pop_front();
	popped = true;
	if (model->masks.dl_sched.empty())
	    break;
	top = model->masks.dl_sched.front();
      }
      if (top.start > nowf)
	dl_next_start = top.start;
      /*
       * Have to push the current one back to the sched, if it is still
       * current.  Artifact of the API and this impl; fix it later.
       */
      if (popped && (model->masks.dl.end <= 0 || model->masks.dl.end > nowf))
	model->masks.dl_sched.push_front(model->masks.dl);
    }
    /*
     * If the schedule is empty (or just became empty) or its current front
     * is not yet scheduleable, set the default mask, if necessary.
     */
    if (model->masks.dl_sched.empty() || model->masks.dl_sched.front().start > nowf) {
      if (model->masks.dl != model->masks.dl_def) {
	E2SM_DEBUG(model->agent, "zylinium: setting dl mask to default (%s)\n",
		   model->masks.dl_def.mask_str.c_str());
	dl_set = true;
	model->masks.dl = model->masks.dl_def;
      }
    }
    /*
     * Finally, pick the next wakeup time.
     */
    if (model->masks.dl.end > 0.0f)
	dl_next = model->masks.dl.end;
    else if (!model->masks.dl_sched.empty()) {
      double fts = model->masks.dl_sched.front().start;
      if (dl_next_start > 0.0f)
	dl_next = dl_next_start;
      if (fts > nowf && fts < dl_next)
	dl_next = fts;
    }

    /*
     * Now, same for uplink.
     */
    double ul_next_start = 0.0f;
    if (!model->masks.ul_sched.empty()) {
      UlBlockedMask& top = model->masks.ul_sched.front();
      bool popped = false;
      while (top.start < nowf && (top.end < nowf || model->masks.ul.end <= 0)) {
	if (model->masks.ul != top) {
	  E2SM_DEBUG(model->agent, "zylinium: setting ul mask (%s,%f,%f,%d)\n",
		     top.mask_str.c_str(), top.start, top.end, top.id);
	  model->masks.ul = top;
	  ul_set = true;
	}
	model->masks.ul_sched.pop_front();
	popped = true;
	if (model->masks.ul_sched.empty())
	    break;
	top = model->masks.ul_sched.front();
      }
      if (top.start > nowf)
	ul_next_start = top.start;
      if (popped && (model->masks.ul.end <= 0 || model->masks.ul.end > nowf))
	model->masks.ul_sched.push_front(model->masks.ul);
    }
    if (model->masks.ul_sched.empty() || model->masks.ul_sched.front().start > nowf) {
      if (model->masks.ul != model->masks.ul_def) {
	E2SM_DEBUG(model->agent, "zylinium: setting ul mask to default (%s)\n",
		   model->masks.ul_def.mask_str.c_str());
	ul_set = true;
	model->masks.ul = model->masks.ul_def;
      }
    }
    if (model->masks.ul.end > 0.0f)
      ul_next = model->masks.ul.end;
    else if (!model->masks.ul_sched.empty()) {
      double fts = model->masks.ul_sched.front().start;
      if (ul_next_start > 0.0f)
	ul_next = ul_next_start;
      if (fts > nowf && fts < ul_next)
	ul_next = fts;
    }


    /*
     * If anything changed, update the scheduler, and send notifications.
     */
    if (dl_set || ul_set) {
      if (dl_set)
	model->agent->enb_zylinium_interface->set_blocked_rbgmask(model->masks.dl.mask);
      if (ul_set)
	model->agent->enb_zylinium_interface->set_blocked_prbmask(model->masks.ul.mask);

      model->agent->push_task([model]() { model->send_indications(); });
    }

    if (dl_next > 0.0 || ul_next > 0.0) {
      double next = dl_next;
      if (next == 0.0f || ul_next < next)
	next = ul_next;
      E2SM_DEBUG(model->agent, "zylinium: next wait time %f (now %f, %f s)\n",
		 next, nowf, next - nowf);
      int sec = static_cast<int>(next);
      long nsec = static_cast<long>((next - static_cast<double>(sec)) * 1000000000);
      struct timespec ts = { sec, nsec };
      E2SM_DEBUG(model->agent, "zylinium: waiting for %d s %ld ns\n", sec, nsec);
      pthread_cond_timedwait(&model->cond,&model->lock,&ts);
    }
    else {
      E2SM_DEBUG(model->agent, "zylinium: waiting until next schedule change (now %f)\n",
		 nowf);
      pthread_cond_wait(&model->cond,&model->lock);
    }
  }

  return NULL;
}

void zylinium_model::send_indications()
{
  uint8_t *buf = NULL;
  ssize_t buf_len = 0;
  std::list<ric::subscription_t *>::iterator it;
  ric::subscription_t *sub;
  std::list<ric::action_t *>::iterator it2;
  ric::action_t *action;
  E2SM_ZYLINIUM_E2SM_Zylinium_IndicationHeader_t ih;
  E2SM_ZYLINIUM_E2SM_Zylinium_IndicationMessage_t im;
  uint8_t *header_buf = NULL;
  ssize_t header_buf_len = 0;
  uint8_t *msg_buf = NULL;
  ssize_t msg_buf_len = 0;
  MaskStatus masks_copy;

  pthread_mutex_lock(&lock);
  if (subscriptions.size() == 0) {
    pthread_mutex_unlock(&lock);
    return;
  }
  masks_copy = masks;
  pthread_mutex_unlock(&lock);

  E2SM_INFO(agent,"zylinium: sending indications\n");

  /*
   * Second, we generate the e2sm-specific stuff.
   *
   * NB: we really need this to be action-specific, because actions can
   * request a particular report style, but since we currently only
   * generate one report style, don't worry for now.
   */
  memset(&ih,0,sizeof(ih));
  ih.present = E2SM_ZYLINIUM_E2SM_Zylinium_IndicationHeader_PR_indicationType;
  ih.choice.indicationType = E2SM_ZYLINIUM_E2SM_Zylinium_IndicationType_maskStatusReport;

  E2SM_DEBUG(agent,"indication header:\n");
  E2SM_XER_PRINT(NULL,&asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_IndicationHeader,&ih);

  header_buf_len = ric::e2ap::encode(
    &asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_IndicationHeader,0,&ih,&header_buf);
  if (header_buf_len < 0) {
    E2SM_ERROR(agent,"failed to encode indication header; aborting send_indication\n");
    ASN_STRUCT_FREE_CONTENTS_ONLY(
      asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_IndicationHeader,&ih);
    goto out;
  }
  /*
  memset(&ih,0,sizeof(ih));
  if (ric::e2ap::decode(
	agent,&asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_IndicationHeader,&ih,
	header_buf,header_buf_len)) {
    E2SM_ERROR(agent,"failed to redecode e2sm ih\n");
    goto out;
  }
  E2SM_DEBUG(agent,"indication header (decoded):\n");
  E2SM_XER_PRINT(NULL,&asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_IndicationHeader,&ih);
  ASN_STRUCT_FREE_CONTENTS_ONLY(
    asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_IndicationHeader,&ih);
  */

  memset(&im,0,sizeof(im));
  im.present = E2SM_ZYLINIUM_E2SM_Zylinium_IndicationMessage_PR_maskStatusReport;
  encode_mask_status_report(masks_copy, &im.choice.maskStatusReport);

  E2SM_DEBUG(agent,"indication message:\n");
  E2SM_XER_PRINT(NULL,&asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_IndicationMessage,&im);

  msg_buf_len = ric::e2ap::encode(
    &asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_IndicationMessage,0,&im,&msg_buf);
  if (msg_buf_len < 0) {
    E2SM_ERROR(agent,"failed to encode indication msg; aborting send_indication\n");
    ASN_STRUCT_FREE_CONTENTS_ONLY(
      asn_DEF_E2SM_ZYLINIUM_E2SM_Zylinium_IndicationMessage,&im);
    goto out;
  }

  /*
   * Finally, for each subscription and its actions, generate and send
   * an indication.  We could only do this more efficiently if we did
   * all the PDU generation here, because the subscription and action
   * IDs are built into the RICindication message, so we have to
   * generate a new one for each.  This means we are less efficient due
   * to all the memcpys to create the IEs; and the memcpys into temp
   * buffers for the SM-specific octet strings.  Ah well.
   */
  for (it = subscriptions.begin(); it != subscriptions.end(); ++it) {
    sub = *it;
    for (it2 = sub->actions.begin(); it2 != sub->actions.end(); ++it2) {
      action = *it2;

      if (ric::e2ap::generate_indication(
	    agent,sub->request_id,sub->instance_id,sub->function_id,
	    action->id,serial_number++,(int)E2AP_RICindicationType_report,
	    header_buf,header_buf_len,msg_buf,msg_buf_len,NULL,0,&buf,&buf_len)) {
	E2SM_ERROR(
	  agent,"zylinium: failed to generate indication (reqid=%ld,instid=%ld,funcid=%ld,actid=%ld)\n",
	  sub->request_id,sub->instance_id,sub->function_id,action->id);
      }
      else {
	E2SM_DEBUG(
	  agent,"zylinium: sending indication (reqid=%ld,instid=%ld,funcid=%ld,actid=%ld)\n",
	  sub->request_id,sub->instance_id,sub->function_id,action->id);
	agent->send_sctp_data(buf,buf_len);
      }
      free(buf);
      buf = NULL;
      buf_len = 0;
    }
  }

 out:
  pthread_mutex_unlock(&lock);
  return;
}

}
