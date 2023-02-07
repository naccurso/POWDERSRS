#ifndef RIC_E2SM_ZYLINIUM_H
#define RIC_E2SM_ZYLINIUM_H

#include <list>
#include <map>
#include <queue>

#include "pthread.h"

#include "srsenb/hdr/stack/upper/common_enb.h"
#include "srslte/interfaces/enb_metrics_interface.h"
#include "srsenb/hdr/stack/rrc/rrc_metrics.h"

#include "srsenb/hdr/ric/e2ap.h"
#include "srsenb/hdr/ric/e2sm.h"

namespace ric {

class zylinium_model : public service_model
{
public:

  zylinium_model(ric::agent *agent_);
  int init();
  void stop();
  virtual ~zylinium_model() { stop(); };
  int handle_subscription_add(ric::subscription_t *sub);
  int handle_subscription_del(ric::subscription_t *sub,int force,
			      long *cause,long *cause_detail);
  void handle_control(ric::control_t *control);

private:
  std::string blocked_dl_rbg_mask;
  std::string blocked_ul_prb_mask;
  pthread_mutex_t lock;
};

}

#endif
