/**
 * @file librpscan.h
 * @brief Main header for librpscan - nmap wrapper library
 * 
 * This library provides C functions for scanning targets using nmap
 * with various preset configurations and comprehensive XML parsing.
 */

#ifndef LIBRPSCAN_H
#define LIBRPSCAN_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque pointer to scan result data
 */
typedef void *ScanResult;

/**
 * @defgroup scan_functions Scan Functions
 * @{
 */

/**
 * Default scan: Service version detection on top 1000 ports
 * @param target Target host or network address
 * @return Opaque ScanResult pointer
 */
ScanResult scan_target(const char *target);

/**
 * Stealthy scan: Slow SYN stealth scan on 100 ports (T1)
 * @param target Target host or network address
 * @return Opaque ScanResult pointer
 */
ScanResult scan_target_stealthy(const char *target);

/**
 * Aggressive scan: Fast OS detection with NSE scripts (T4 -A)
 * @param target Target host or network address
 * @return Opaque ScanResult pointer
 */
ScanResult scan_target_aggressive(const char *target);

/**
 * Comprehensive scan: Version detection with scripts on 10k ports
 * @param target Target host or network address
 * @return Opaque ScanResult pointer
 */
ScanResult scan_target_comprehensive(const char *target);

/**
 * UDP scan: UDP protocol detection on common ports
 * @param target Target host or network address
 * @return Opaque ScanResult pointer
 */
ScanResult scan_target_udp(const char *target);

/**
 * All ports scan: Full TCP port range (WARNING: slow)
 * @param target Target host or network address
 * @return Opaque ScanResult pointer
 */
ScanResult scan_target_all_ports(const char *target);

/**
 * OS detection scan: Operating system fingerprinting
 * @param target Target host or network address
 * @return Opaque ScanResult pointer
 */
ScanResult scan_target_os_detection(const char *target);

/**
 * Custom scan: Use your own nmap flags
 * @param target Target host or network address
 * @param flags Custom nmap flags (e.g., "-T4 -A -sV")
 * @return Opaque ScanResult pointer
 */
ScanResult scan_target_custom(const char *target, const char *flags);

/** @} */

/**
 * @defgroup accessor_functions Accessor Functions
 * @{
 */

/**
 * @defgroup summary_accessors Summary Accessors
 * @{
 */
int get_summary_count(ScanResult r);
const char *get_summary_line(ScanResult r, int i);
/** @} */

/**
 * @defgroup port_accessors Port Accessors
 * @{
 */
int get_port_count(ScanResult r);
const char *get_port_row(ScanResult r, int i);
/** @} */

/**
 * @defgroup service_accessors Service Accessors
 * @{
 */
int get_serviceinfo_count(ScanResult r);
const char *get_serviceinfo_line(ScanResult r, int i);
int get_servicedetails_count(ScanResult r);
const char *get_servicedetails_line(ScanResult r, int i);
/** @} */

/**
 * @defgroup os_accessors OS Detection Accessors
 * @{
 */
int get_osdetection_count(ScanResult r);
const char *get_osdetection_line(ScanResult r, int i);
int get_osmatches_count(ScanResult r);
const char *get_osmatches_line(ScanResult r, int i);
int get_osclasses_count(ScanResult r);
const char *get_osclasses_line(ScanResult r, int i);
/** @} */

/**
 * @defgroup host_accessors Host Accessors
 * @{
 */
int get_hostinfo_count(ScanResult r);
const char *get_hostinfo_line(ScanResult r, int i);
int get_hostnames_count(ScanResult r);
const char *get_hostnames_line(ScanResult r, int i);
/** @} */

/**
 * @defgroup script_accessors Script Accessors
 * @{
 */
int get_scripts_count(ScanResult r);
const char *get_scripts_line(ScanResult r, int i);
/** @} */

/**
 * @defgroup traceroute_accessors Traceroute Accessors
 * @{
 */
int get_traceroute_count(ScanResult r);
const char *get_traceroute_line(ScanResult r, int i);
/** @} */

/**
 * @defgroup portdetails_accessors Port Details Accessors
 * @{
 */
int get_portdetails_count(ScanResult r);
const char *get_portdetails_line(ScanResult r, int i);
/** @} */

/**
 * Free scan result resources
 * @param r ScanResult pointer to free
 */
void free_scan_result(ScanResult r);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* LIBRPSCAN_H */
