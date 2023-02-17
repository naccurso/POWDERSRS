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

class BlockedMask
{
public:
  BlockedMask()
    : mask_str("0x0"),start(0.0f),end(0.0f),id(0) {};
  BlockedMask(const std::string& mask_str_,double start_,double end_,int id_)
    : mask_str(mask_str_),start(start_),end(end_),id(id_) { };
  bool operator==(const BlockedMask& other) const noexcept
  {
    return (mask_str == other.mask_str
	    && start == other.start
	    && end == other.end
	    && id == other.id);
  };
  bool operator!=(const BlockedMask& other) const noexcept
  {
    return (mask_str != other.mask_str
	    || start != other.start
	    || end != other.end
	    || id != other.id);
  };

  std::string mask_str;
  double start;
  double end;
  int id;
};

class DlBlockedMask : public BlockedMask
{
public:
  DlBlockedMask()
    : BlockedMask(),mask(25) {};
  DlBlockedMask(srsenb::rbgmask_t& mask_,const std::string& mask_str_,double start_,double end_,int id_)
    : mask(mask_),BlockedMask(mask_str_,start_,end_,id_) { };
  bool operator==(const DlBlockedMask& other) const noexcept
  {
    return (mask == other.mask && BlockedMask::operator==(other));
  };
  bool operator!=(const DlBlockedMask& other) const noexcept
  {
    return (mask != other.mask || BlockedMask::operator!=(other));
  };

  srsenb::rbgmask_t mask;
};

class UlBlockedMask : public BlockedMask
{
public:
  UlBlockedMask()
    : BlockedMask(),mask(100) {};
  UlBlockedMask(srsenb::prbmask_t& mask_,const std::string& mask_str_,double start_,double end_,int id_)
    : mask(mask_),BlockedMask(mask_str_,start_,end_,id_) { };
  bool operator==(const UlBlockedMask& other) const noexcept
  {
    return (mask == other.mask && BlockedMask::operator==(other));
  };
  bool operator!=(const UlBlockedMask& other) const noexcept
  {
    return (mask != other.mask && BlockedMask::operator!=(other));
  };

  srsenb::prbmask_t mask;
};

class MaskStatus
{
public:
  MaskStatus()
    : dl(),ul(),dl_def(),ul_def(),dl_sched(),ul_sched() {};
  MaskStatus(DlBlockedMask& dl_def_,UlBlockedMask& ul_def_,
	     std::list<DlBlockedMask>& dl_sched_,
	     std::list<UlBlockedMask>& ul_sched_)
    : dl(),ul(),dl_def(dl_def_),ul_def(ul_def_),
      dl_sched(dl_sched_),ul_sched(ul_sched_) {};

  DlBlockedMask dl;
  UlBlockedMask ul;
  DlBlockedMask dl_def;
  UlBlockedMask ul_def;
  std::list<DlBlockedMask> dl_sched;
  std::list<UlBlockedMask> ul_sched;
};

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
  void send_indications();
  static void *run(void *arg);

private:
  std::list<ric::subscription_t *> subscriptions;
  long serial_number;
  MaskStatus masks;
  pthread_mutex_t lock;
  pthread_t thread;
  pthread_cond_t cond;
  bool running;
};

}

#endif
