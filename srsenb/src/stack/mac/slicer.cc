#include "srslte/common/logmap.h"
#include "srsenb/hdr/enb.h"
#include "srsenb/hdr/stack/mac/slicer.h"
#include <string>
#include <fstream>
#include <iostream>
#include <vector>

namespace slicer {

slicer::slicer() {}
slicer::~slicer() {}

void slicer::init(const srsenb::slicer_args_t& args_)
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  if (!args_.test_agent_interface && !args_.slice_db_filename.empty()) {
    if (!read_slice_db_file(args_.slice_db_filename)) {
      srslte::console("[slicer] Couldn't read slice_db file: %s\n", args_.slice_db_filename.c_str());
      exit(SRSLTE_ERROR);
    }
  }

  workshare = args_.workshare;
  enable = args_.enable;
  sliced_unsliced_ratio = args_.sliced_unsliced_ratio;
  initialized = true;
}

std::vector<uint16_t> slicer::get_cur_sf_crntis(uint32_t tti_tx_dl)
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  if (!has_alloc) {
    return {};
  }

  // if enabled, preserve unsliced subframe
  if (sliced_unsliced_ratio && (tti_tx_dl % sliced_unsliced_ratio == 0)) {
    return {};
  } else {
    slice_iter = slices.begin();
    // std::cout << alloc_index << " " << sf_alloc[alloc_index] << " ";
    std::advance(slice_iter, sf_alloc[alloc_index]);
    alloc_index++;
    if (alloc_index == total_sf_alloc) {
      alloc_index = 0;
      // std::cout << "\n";
    }
    return slice_to_crnti_vec[slice_iter->first];
  }
}

std::vector<uint16_t> slicer::get_all_slice_crntis()
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  if (!has_alloc) {
    return {};
  }

  return all_slice_crntis;
}

std::vector<slice_status_t> slicer::slice_status(std::vector<std::string> slice_names)
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  srslte::console("[slicer] getting slice status...\n");
  std::vector<slice_status_t> ret;
  if (slice_names.empty()) {
    for (slice_iter = slices.begin(); slice_iter != slices.end(); ++slice_iter) {
      ret.push_back(slice_iter->second);
    }
  }
  else {
    for (auto it = slice_names.begin(); it != slice_names.end(); ++it) {
      auto it1 = slices.find(*it);
      if (it1 != slices.end()) {
        ret.push_back(it1->second);
      }
    }
  }

  return ret;
}

bool slicer::slice_config(std::vector<slice_config_t> slice_configs)
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  srslte::console("[slicer] configuring slices...\n");
  for (auto it = slice_configs.begin(); it != slice_configs.end(); ++it) {
    slice_t s;
    s.config.name = it->name;
    s.config.prop_alloc_policy = it->prop_alloc_policy;
    slices[s.config.name] = s;
  }
  upd_sf_alloc();
  return true;
}

bool slicer::slice_ue_bind(std::string slice_name, std::vector<uint64_t> imsi_list)
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  srslte::console("[slicer] binding UEs to slice...\n");
  auto s_it = slices.find(slice_name);
  if (s_it == slices.end()) {
    srslte::console("[slicer] slice %s does not exist!\n", slice_name.c_str());
    return false;
  }

  for (auto it = imsi_list.begin(); it != imsi_list.end(); ++it) {
    auto it2 = std::find(s_it->second.imsi_list.begin(),
                         s_it->second.imsi_list.end(), *it);
    if (it2 == s_it->second.imsi_list.end()) {
      s_it->second.imsi_list.push_back(*it);
      srslte::console("[slicer] slice %s bound to IMSI %lu\n",
		      slice_name.c_str(),*it);
    }
  }
  upd_slice_crntis(slice_name);

  return true;
}

bool slicer::slice_ue_unbind(std::string slice_name, std::vector<uint64_t> imsi_list)
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  srslte::console("[slicer] unbinding UEs from slice...\n");
  auto s_it = slices.find(slice_name);
  if (s_it == slices.end()) {
    srslte::console("[slicer] slice %s does not exist!\n", slice_name.c_str());
    return false;
  }

  for (auto it = imsi_list.begin(); it != imsi_list.end(); ++it) {
    auto it2 = std::find(s_it->second.imsi_list.begin(),
                         s_it->second.imsi_list.end(), *it);
    if (it2 != s_it->second.imsi_list.end()) {
      srslte::console("[slicer] slice %s unbound from IMSI %lu\n",
		      slice_name.c_str(),*it);
      s_it->second.imsi_list.erase(it2);
    }
  }
  upd_slice_crntis(slice_name);

  return true;
}

bool slicer::slice_delete(std::vector<std::string> slice_names)
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  srslte::console("[slicer] deleting slices...\n");
  for (auto it = slice_names.begin(); it != slice_names.end(); ++it) {
    auto s = slices.find(*it);
    if (s != slices.end()) {
      slices.erase(s);
      slice_to_crnti_vec.erase(*it);
    }
  }
  upd_sf_alloc();
  return false;
}

int slicer::upd_member_crnti(uint64_t imsi, uint16_t crnti)
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  imsi_to_crnti[imsi] = crnti;
  srslte::console("[slicer] updated IMSI: %015" PRIu64 " with RNTI: 0x%x\n", imsi, crnti);

  for (slice_iter = slices.begin(); slice_iter != slices.end(); ++slice_iter) {
    std::vector<uint64_t> *s_imsis = &slice_iter->second.imsi_list;
    if (std::find(s_imsis->begin(), s_imsis->end(), imsi) != s_imsis->end()) {
      srslte::console("[slicer] RNTI 0x%x belongs to slice %s\n", crnti, slice_iter->first.c_str());
      upd_slice_crntis(slice_iter->first);
    }
  }
  return 0;
}

int slicer::upd_member_crnti(uint32_t tmsi, uint16_t crnti)
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  if (tmsi_to_imsi.find(tmsi) == tmsi_to_imsi.end()) {
    srslte::console("[slicer] new TMSI: %u with RNTI: 0x%x\n", tmsi, crnti);
    tmsi_to_imsi[tmsi] = 0;
  }

  for (auto it = imsi_to_crnti.begin(); it != imsi_to_crnti.end(); ++it) {
    if (it->second == crnti) {
      tmsi_to_imsi[tmsi] = it->first;
      srslte::console("[slicer] updated TMSI: %u for IMSI: %015" PRIu64 " and RNTI: 0x%x\n",
                      tmsi, it->first, crnti);
      break;
    }
  }

  if (tmsi_to_imsi[tmsi] == 0) {
    srslte::console("[slicer] TMSI: %u for RNTI: 0x%x not yet mapped to an IMSI\n", tmsi, crnti);
    srslte::console("[slicer] will not update slice crntis.\n");
    return 0;
  }

  for (slice_iter = slices.begin(); slice_iter != slices.end(); ++slice_iter) {
    std::vector<uint64_t> *s_imsis = &slice_iter->second.imsi_list;
    auto it = std::find(s_imsis->begin(), s_imsis->end(), tmsi_to_imsi[tmsi]);
    if (it != s_imsis->end()) {
      imsi_to_crnti[*it] = crnti;
      srslte::console("[slicer] RNTI: 0x%x belongs to slice %s\n", crnti, slice_iter->first.c_str());
      upd_slice_crntis(slice_iter->first);
    }
  }
  return 0;
}

int slicer::upd_member_crnti(uint16_t old_crnti, uint16_t new_crnti)
{
  std::lock_guard<std::mutex> lock(slicer_mutex);
  srslte::console("[slicer] updating RNTI: 0x%x with RNTI: 0x%x\n", old_crnti, new_crnti);
  for (auto it = imsi_to_crnti.begin(); it != imsi_to_crnti.end(); ++it) {
    if (it->second == old_crnti) {
      it->second = new_crnti;
      auto imsi = it->first;
      srslte::console("[slicer] updated RNTI for IMSI: %015" PRIu64 " from 0x%x to 0x%x\n",
                      imsi, old_crnti, new_crnti);
      for (slice_iter = slices.begin(); slice_iter != slices.end(); ++slice_iter) {
        std::vector<uint64_t> *s_imsis = &slice_iter->second.imsi_list;
        if (std::find(s_imsis->begin(), s_imsis->end(), imsi) != s_imsis->end()) {
          srslte::console("[slicer] new RNTI 0x%x belongs to slice %s\n", new_crnti, slice_iter->first.c_str());
          upd_slice_crntis(slice_iter->first);
        }
      }
      break;
    }
  }

  return 0;
}

bool slicer::read_slice_db_file(std::string db_filename)
{
  std::ifstream m_db_file;

  m_db_file.open(db_filename.c_str(), std::ifstream::in);
  if (!m_db_file.is_open()) {
    return false;
  }
  srslte::console("[slicer] opened slice DB file: %s\n", db_filename.c_str());

  std::string line;
  while (std::getline(m_db_file, line)) {
    if (line[0] != '#' && line.length() > 0) {
      slice_t s;
      std::vector<std::string> split = split_string(line, ',');
      s.config.name = split[0];
      s.config.prop_alloc_policy.share = static_cast<uint32_t>(std::stoul(split[1]));
      std::vector<std::string>::iterator it = split.begin() + 2;

      while (it != split.end()) {
        s.imsi_list.push_back(std::stoul(it->c_str()));
        ++it;
      }

      int ret = add_slice(s);
      if (ret != 0) {
        srslte::console("[slicer] failed to add slice %s, check file format\n", s.config.name.c_str());
        m_db_file.close();
        exit(SRSLTE_ERROR);
      }
    }
  }

  m_db_file.close();
  upd_sf_alloc();
  return true;
}

// still used when slice configuration loaded from file
int slicer::add_slice(slice_t slice)
{
  // add slice if it doesn't exist
  if (slices.find(slice.config.name) != slices.end()) {
    return -1;
  }

  slices[slice.config.name] = slice;

  srslte::console("[slicer] added slice %s with n_sf=%u and member IMSIs=",
                  slice.config.name.c_str(), slice.config.prop_alloc_policy.share);
  for (auto it = slice.imsi_list.begin(); it < slice.imsi_list.end(); ++it) {
    srslte::console("%015" PRIu64 " ", *it);
  }
  srslte::console("\n");
  return 0;
}

/**
 * Given the proportional share for all slices, use their greatest common factor
 * to produce the smallest total subframe allocation that maintains
 * proportionality.
 */
void slicer::upd_sf_alloc()
{
  srslte::console("[slicer] updating proportional sf allocation...\n");
  std::vector<uint32_t> slice_shares;
  std::map<std::string, slice>::iterator it;
  for (it = slices.begin(); it != slices.end(); ++it) {
    slice_shares.push_back(it->second.config.prop_alloc_policy.share);
  }
  uint32_t gcf = calc_gcf_vec(slice_shares);
  // srslte::console("gcf: %u", gcf);
  total_sf_alloc = 0;
  sf_alloc.clear();
  uint32_t slice_cnt = 0, tmp = 0;
  for (it = slices.begin(); it != slices.end(); ++it, ++slice_cnt) {
    tmp = it->second.config.prop_alloc_policy.share / gcf;
    total_sf_alloc += tmp;
    sf_alloc.insert(sf_alloc.end(), tmp, slice_cnt);
    srslte::console("[slicer] slice: %s, proportional sf allocation: %u\n", it->first.c_str(), tmp);
  }

  has_alloc = total_sf_alloc > 0;
}

void slicer::upd_slice_crntis(std::string s_name)
{
  slice_to_crnti_vec[s_name].clear();
  std::vector<uint64_t>::iterator it = slices[s_name].imsi_list.begin();
  for (; it != slices[s_name].imsi_list.end(); ++it) {
    if (imsi_to_crnti.find(*it) != imsi_to_crnti.end()) {
      slice_to_crnti_vec[s_name].push_back(imsi_to_crnti[*it]);
    }
  }
  srslte::console("[slicer] updated RNTIs for slice %s\n", s_name.c_str());
  srslte::console("[slicer] RNTIs: ");
  for (auto it = slice_to_crnti_vec[s_name].begin(); it != slice_to_crnti_vec[s_name].end(); ++it) {
    srslte::console("0x%x ", *it);
  }
  srslte::console("\n");

  all_slice_crntis.clear();
  for (auto it = slice_to_crnti_vec.begin(); it != slice_to_crnti_vec.end(); ++it) {
    for (auto it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
      all_slice_crntis.push_back(*it2);
    }
  }
}

// helper functions
std::vector<std::string> split_string(const std::string& str, char delimiter)
{
  std::vector<std::string> tokens;
  std::string              token;
  std::istringstream       tokenstream(str);

  while (std::getline(tokenstream, token, delimiter)) {
    tokens.push_back(token);
  }
  return tokens;
}

/**
 * We use the GCF to reduce the proportional slice allocation (currently read
 * from file) to the smallest total subframe allocation.
 */
uint32_t calc_gcf(uint32_t a, uint32_t b)
{
  if (a == 0) {
    return b;
  }

  return calc_gcf(b % a, a);
}

uint32_t calc_gcf_vec(std::vector<uint32_t> v)
{
  auto res = v[0];
  for (uint32_t i = 1; i < v.size(); i++)
  {
    res = calc_gcf(v[i], res);
    if(res == 1)
    {
      return 1;
    }
  }
  return res;
}

} // namespace slicer
