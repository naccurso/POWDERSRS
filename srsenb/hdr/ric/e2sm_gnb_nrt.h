#ifndef RIC_E2SM_GNB_NRT_H
#define RIC_E2SM_GNB_NRT_H

#include "srsenb/hdr/ric/e2ap.h"
#include "srsenb/hdr/ric/e2sm.h"

namespace ric {

class gnb_nrt_model : public service_model
{
public:
  gnb_nrt_model(ric::agent *agent_): service_model(agent) {};
  int init();
  virtual ~gnb_nrt_model() {};

  const std::string name = "ORAN-E2SM-gNB-NRT";
  const std::string oid = "1.3.6.1.4.1.28458.99.0.21.3.3.1.3";

private:
  int handle_subscription_add(ric::subscription_t *sub);
  int handle_subscription_del(ric::subscription_t *sub,int force,
			      long *cause,long *cause_detail);
  int handle_control(ric::control_t *control);
  
  ric::agent *agent;
};

}

#endif
