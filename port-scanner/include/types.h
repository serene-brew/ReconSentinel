/**
 * @file types.h
 * @brief Data types and structures for librpscan
 */

#ifndef LIBRPSCAN_TYPES_H
#define LIBRPSCAN_TYPES_H

#include <string>
#include <vector>

/**
 * Internal data structure holding all scan result information
 * 
 * Organized into logical categories:
 * - Basic: Summary, ports, service tree
 * - Enhanced: Service details, OS detection, NSE scripts
 * - Host-level: Host addresses, hostnames
 * - OS matching: OS matches and classes
 * - Network: Traceroute information
 * - Advanced: Port state details
 */
struct ScanResultInternal {
  // ========== Basic Information ==========
  /// Summary lines (version, start time, duration, host state)
  std::vector<std::string> summary;
  
  /// Open ports (port\tprotocol\tservice\tproduct\tversion)
  std::vector<std::string> ports;
  
  /// Service information tree (OSes, CPEs)
  std::vector<std::string> service_tree;
  
  // ========== Enhanced Detailed Information ==========
  /// Port-level service info (ostype, extrainfo, hostname, tunnel, conf, method)
  std::vector<std::string> service_details;
  
  /// Detected OSes from port services
  std::vector<std::string> os_detection;
  
  /// NSE script output
  std::vector<std::string> scripts_output;
  
  // ========== Host-Level Information ==========
  /// Host addresses (IPv4, IPv6, MAC with vendor info)
  std::vector<std::string> host_info;
  
  /// Hostnames (reverse DNS)
  std::vector<std::string> hostnames;
  
  // ========== OS Matching Details ==========
  /// OS detection matches with accuracy percentages
  std::vector<std::string> os_matches;
  
  /// OS classification (type, vendor, family, generation)
  std::vector<std::string> os_classes;
  
  // ========== Network Information ==========
  /// Traceroute hop-by-hop data
  std::vector<std::string> traceroute_data;
  
  // ========== Advanced Port Information ==========
  /// Port state reasons and TTL information
  std::vector<std::string> port_details;
};

#endif /* LIBRPSCAN_TYPES_H */
