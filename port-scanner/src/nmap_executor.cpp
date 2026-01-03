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

std::string run_nmap_with_flags_and_cookies(const std::string &target,
                                            const std::string &flags,
                                            const std::string &cookies) {
  std::string cmd = "nmap " + flags;
  
  // Add cookie support via script-args if cookies are provided
  if (!cookies.empty()) {
    // Escape special characters in cookies for shell safety
    std::string escaped_cookies = cookies;
    // Escape quotes and semicolons that might break the command
    size_t pos = 0;
    while ((pos = escaped_cookies.find('"', pos)) != std::string::npos) {
      escaped_cookies.insert(pos, "\\");
      pos += 2;
    }
    // Use single quotes to wrap the entire script-args value
    cmd += " --script-args 'http.cookie=" + escaped_cookies + "'";
  }
  
  cmd += " --no-stylesheet -oX - " + target + " 2>/dev/null";

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
