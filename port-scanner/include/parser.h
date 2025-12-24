/**
 * @file parser.h
 * @brief XML parsing interface for nmap results
 */

#ifndef LIBRPSCAN_PARSER_H
#define LIBRPSCAN_PARSER_H

#include <string>
#include "types.h"

/**
 * Parse nmap XML output and populate scan result
 * 
 * Extracts:
 * - Summary information (version, start time, duration, host state)
 * - Host addresses and hostnames
 * - Open ports with service information
 * - Port state details (reason, TTL)
 * - Service attributes (ostype, extrainfo, tunnel, confidence, method)
 * - NSE script output
 * - OS detection matches with accuracy
 * - OS classification details
 * - Traceroute hop-by-hop information
 * 
 * @param xml XML string from nmap output
 * @param res Pointer to ScanResultInternal to populate
 */
void parse_nmap_result(const std::string &xml, ScanResultInternal *res);

#endif /* LIBRPSCAN_PARSER_H */
