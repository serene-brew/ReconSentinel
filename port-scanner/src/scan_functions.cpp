/**
 * @file scan_functions.cpp
 * @brief Implementation of scan preset functions
 */

#include "librpscan.h"
#include "types.h"
#include "nmap_executor.h"
#include "parser.h"

/* ================= Main entry ================= */

ScanResult scan_target(const char *target) {
  auto *res = new ScanResultInternal;
  std::string xml = run_nmap(target);
  parse_nmap_result(xml, res);
  return res;
}

/* ================= Scan Presets ================= */

ScanResult scan_target_stealthy(const char *target) {
  auto *res = new ScanResultInternal;
  std::string xml = run_nmap_with_flags(
      target, "-T1 -sS -sV --top-ports 100");
  parse_nmap_result(xml, res);
  return res;
}

ScanResult scan_target_aggressive(const char *target) {
  auto *res = new ScanResultInternal;
  std::string xml = run_nmap_with_flags(
      target, "-T4 -A");
  parse_nmap_result(xml, res);
  return res;
}

ScanResult scan_target_comprehensive(const char *target) {
  auto *res = new ScanResultInternal;
  std::string xml = run_nmap_with_flags(
      target, "-T4 -sV -sC --top-ports 10000");
  parse_nmap_result(xml, res);
  return res;
}

ScanResult scan_target_udp(const char *target) {
  auto *res = new ScanResultInternal;
  std::string xml = run_nmap_with_flags(
      target, "-T4 -sU --top-ports 1000");
  parse_nmap_result(xml, res);
  return res;
}

ScanResult scan_target_all_ports(const char *target) {
  auto *res = new ScanResultInternal;
  std::string xml = run_nmap_with_flags(
      target, "-T4 -p-");
  parse_nmap_result(xml, res);
  return res;
}

ScanResult scan_target_os_detection(const char *target) {
  auto *res = new ScanResultInternal;
  std::string xml = run_nmap_with_flags(
      target, "-O -sV --top-ports 1000");
  parse_nmap_result(xml, res);
  return res;
}

/* ================= Custom Scan ================= */

ScanResult scan_target_custom(const char *target, const char *flags) {
  auto *res = new ScanResultInternal;
  std::string xml = run_nmap_with_flags(target, flags);
  parse_nmap_result(xml, res);
  return res;
}
