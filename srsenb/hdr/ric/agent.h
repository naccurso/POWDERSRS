#ifndef RIC_AGENT_H
#define RIC_AGENT_H

#include <list>
#include <map>

#include <sys/socket.h>

#include "srslte/common/common.h"
#include "srslte/common/log.h"
#include "srslte/common/logger_file.h"
#include "srslte/common/log_filter.h"
#include "srslte/common/network_utils.h"
#include "srsenb/hdr/enb.h"
#include "srsenb/hdr/ric/e2ap.h"
#include "srsenb/hdr/ric/e2sm.h"

namespace ric {

typedef enum {
  RIC_UNINITIALIZED = 0,
  RIC_INITIALIZED = 1,
  RIC_CONNECTED = 2,
  RIC_ESTABLISHED = 3,
  RIC_FAILURE = 4,
  RIC_DISCONNECTED = 5,
  RIC_DISABLED = 6,
} agent_state_t;

class agent
{
public:
  agent(srslte::logger *logger_);
  virtual ~agent();

  int init(const srsenb::all_args_t& args_);
  int start();
  void stop();
  int reset();
  bool send_sctp_data(uint8_t *buf,ssize_t len);
  bool is_function_enabled(std::string &function_name);
  void set_state(agent_state_t state_) { state = state_; };
  void set_ric_id(uint32_t id,uint16_t mcc,uint16_t mnc);
  ric::ran_function_t *lookup_ran_function(ran_function_id_t function_id);
  ric::subscription_t *lookup_subscription(long request_id,long instance_id,
					   ric::ran_function_id_t function_id);

  srslte::logger *logger = nullptr;
  struct {
    srslte::log_filter ric;
    srslte::log_filter e2ap;
    srslte::log_filter e2sm;
    srslte::LOG_LEVEL_ENUM ric_level;
    srslte::LOG_LEVEL_ENUM e2ap_level;
    srslte::LOG_LEVEL_ENUM e2sm_level;
  } log;
  srsenb::all_args_t args;
  std::list<ric::service_model *> service_models;

private:
  bool handle_message(srslte::unique_byte_buffer_t pdu,
		      const sockaddr_in &from,const sctp_sndrcvinfo &sri,
		      int flags);

  agent_state_t state;
  std::map<ric::ran_function_id_t,ric::ran_function_t *> function_id_map;
  std::list<subscription_t *> subscriptions;
  srslte::socket_handler_t ric_socket;
  uint16_t ric_mcc,ric_mnc;
  uint32_t ric_id;
  struct sockaddr_in ric_sockaddr = {};
  std::unique_ptr<srslte::rx_multisocket_handler> rx_sockets;

  std::list<std::string> functions_disabled;
  std::string remote_ipv4_addr;
  uint16_t remote_port;
};

#define RIC_DEBUG(msg,args...) log.ric.debug(msg,##args)
#define RIC_INFO(msg,args...) log.ric.info(msg,##args)
#define RIC_WARN(msg,args...) log.ric.warning(msg,##args)
#define RIC_ERROR(msg,args...) log.ric.error(msg,##args)

#define E2AP_DEBUG(agent,msg,args...) (agent)->log.e2ap.debug(msg,##args)
#define E2AP_INFO(agent,msg,args...) (agent)->log.e2ap.info(msg,##args)
#define E2AP_WARN(agent,msg,args...) (agent)->log.e2ap.warning(msg,##args)
#define E2AP_ERROR(agent,msg,args...) (agent)->log.e2ap.error(msg,##args)

#define E2SM_DEBUG(agent,msg,args...) (agent)->log.e2sm.debug(msg,##args)
#define E2SM_INFO(agent,msg,args...) (agent)->log.e2sm.info(msg,##args)
#define E2SM_WARN(agent,msg,args...) (agent)->log.e2sm.warning(msg,##args)
#define E2SM_ERROR(agent,msg,args...) (agent)->log.e2sm.error(msg,##args)

}

#endif
