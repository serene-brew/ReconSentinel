/**
 * @file accessors.cpp
 * @brief Implementation of C accessor functions for ScanResult
 */

#include "librpscan.h"
#include "types.h"

/* ================= Summary Accessors ================= */

int get_summary_count(ScanResult r) {
  return ((ScanResultInternal *)r)->summary.size();
}

const char *get_summary_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->summary[i].c_str();
}

/* ================= Port Accessors ================= */

int get_port_count(ScanResult r) {
  return ((ScanResultInternal *)r)->ports.size();
}

const char *get_port_row(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->ports[i].c_str();
}

/* ================= Service Info Accessors ================= */

int get_serviceinfo_count(ScanResult r) {
  return ((ScanResultInternal *)r)->service_tree.size();
}

const char *get_serviceinfo_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->service_tree[i].c_str();
}

int get_servicedetails_count(ScanResult r) {
  return ((ScanResultInternal *)r)->service_details.size();
}

const char *get_servicedetails_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->service_details[i].c_str();
}

/* ================= OS Detection Accessors ================= */

int get_osdetection_count(ScanResult r) {
  return ((ScanResultInternal *)r)->os_detection.size();
}

const char *get_osdetection_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->os_detection[i].c_str();
}

int get_osmatches_count(ScanResult r) {
  return ((ScanResultInternal *)r)->os_matches.size();
}

const char *get_osmatches_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->os_matches[i].c_str();
}

int get_osclasses_count(ScanResult r) {
  return ((ScanResultInternal *)r)->os_classes.size();
}

const char *get_osclasses_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->os_classes[i].c_str();
}

/* ================= Host Accessors ================= */

int get_hostinfo_count(ScanResult r) {
  return ((ScanResultInternal *)r)->host_info.size();
}

const char *get_hostinfo_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->host_info[i].c_str();
}

int get_hostnames_count(ScanResult r) {
  return ((ScanResultInternal *)r)->hostnames.size();
}

const char *get_hostnames_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->hostnames[i].c_str();
}

/* ================= Script Accessors ================= */

int get_scripts_count(ScanResult r) {
  return ((ScanResultInternal *)r)->scripts_output.size();
}

const char *get_scripts_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->scripts_output[i].c_str();
}

/* ================= Traceroute Accessors ================= */

int get_traceroute_count(ScanResult r) {
  return ((ScanResultInternal *)r)->traceroute_data.size();
}

const char *get_traceroute_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->traceroute_data[i].c_str();
}

/* ================= Port Details Accessors ================= */

int get_portdetails_count(ScanResult r) {
  return ((ScanResultInternal *)r)->port_details.size();
}

const char *get_portdetails_line(ScanResult r, int i) {
  return ((ScanResultInternal *)r)->port_details[i].c_str();
}

/* ================= Memory Management ================= */

void free_scan_result(ScanResult r) { delete (ScanResultInternal *)r; }
