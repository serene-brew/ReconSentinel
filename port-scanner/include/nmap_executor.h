/**
 * @file nmap_executor.h
 * @brief Nmap command execution interface
 */

#ifndef LIBRPSCAN_NMAP_EXECUTOR_H
#define LIBRPSCAN_NMAP_EXECUTOR_H

#include <string>

/**
 * Execute default nmap scan and return XML output
 * @param target Target host or network address
 * @return XML string from nmap output
 */
std::string run_nmap(const std::string &target);

/**
 * Execute nmap with custom flags and return XML output
 * @param target Target host or network address
 * @param flags Additional nmap flags (e.g., "-T4 -A")
 * @return XML string from nmap output
 */
std::string run_nmap_with_flags(const std::string &target,
                                 const std::string &flags);

/**
 * Execute nmap with custom flags and optional cookies, return XML output
 * @param target Target host or network address
 * @param flags Additional nmap flags (e.g., "-T4 -A")
 * @param cookies Optional cookies string (e.g., "cookie1; cookie2" or "name=value")
 * @return XML string from nmap output
 */
std::string run_nmap_with_flags_and_cookies(const std::string &target,
                                            const std::string &flags,
                                            const std::string &cookies);

#endif /* LIBRPSCAN_NMAP_EXECUTOR_H */
