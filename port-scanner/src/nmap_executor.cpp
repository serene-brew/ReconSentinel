/**
 * @file nmap_executor.cpp
 * @brief Implementation of nmap command execution
 */

#include "nmap_executor.h"
#include <cstdio>
#include <cstdlib>

std::string run_nmap(const std::string &target) {
  std::string cmd = "nmap -sV --top-ports 1000 --no-stylesheet -oX - " +
                    target + " 2>/dev/null";

  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe)
    return "";

  char buf[4096];
  std::string xml;
  while (fgets(buf, sizeof(buf), pipe))
    xml += buf;

  pclose(pipe);
  return xml;
}

std::string run_nmap_with_flags(const std::string &target,
                                 const std::string &flags) {
  std::string cmd = "nmap " + flags + " --no-stylesheet -oX - " + target +
                    " 2>/dev/null";

  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe)
    return "";

  char buf[4096];
  std::string xml;
  while (fgets(buf, sizeof(buf), pipe))
    xml += buf;

  pclose(pipe);
  return xml;
}
