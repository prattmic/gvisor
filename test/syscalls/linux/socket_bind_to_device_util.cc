// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "test/syscalls/linux/socket_bind_to_device_util.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace gvisor {
namespace testing {

Tunnel::Tunnel(std::string tunnel_name) {
  fd_ = open("/dev/net/tun", O_RDWR);
  if (fd_ < 0) {
    return;
  }

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN;
  strncpy(ifr.ifr_name, tunnel_name.c_str(), sizeof(ifr.ifr_name));

  int err = ioctl(fd_, (TUNSETIFF), (void*)&ifr);
  if (err < 0) {
    close(fd_);
    fd_ = -1;
  }
  name_ = ifr.ifr_name;
}

std::unordered_set<string> get_interface_names() {
  struct if_nameindex* interfaces = if_nameindex();
  if (interfaces == nullptr) {
    return {};
  }
  std::unordered_set<string> names;
  for (auto interface = interfaces;
       interface->if_index != 0 || interface->if_name != nullptr; interface++) {
    names.insert(interface->if_name);
  }
  if_freenameindex(interfaces);
  return names;
}

}  // namespace testing
}  // namespace gvisor
