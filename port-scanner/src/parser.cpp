/**
 * @file parser.cpp
 * @brief Implementation of nmap XML parsing
 */

#include "parser.h"
#include <set>
#include <tinyxml2.h>

using namespace tinyxml2;

void parse_nmap_result(const std::string &xml, ScanResultInternal *res) {
  XMLDocument doc;
  if (doc.Parse(xml.c_str()) != XML_SUCCESS)
    return;

  XMLElement *nmaprun = doc.FirstChildElement("nmaprun");
  if (!nmaprun)
    return;

  /* ---- Summary ---- */
  if (const char *ver = nmaprun->Attribute("version"))
    res->summary.push_back(std::string("Nmap version: ") + ver);

  if (const char *start = nmaprun->Attribute("startstr"))
    res->summary.push_back(std::string("Started at: ") + start);

  XMLElement *finished =
      nmaprun->FirstChildElement("runstats")->FirstChildElement("finished");

  if (finished && finished->Attribute("elapsed"))
    res->summary.push_back(std::string("Duration: ") +
                           finished->Attribute("elapsed") + "s");

  /* ---- Host ---- */
  XMLElement *host = nmaprun->FirstChildElement("host");
  if (!host)
    return;

  XMLElement *status = host->FirstChildElement("status");
  if (status && status->Attribute("state"))
    res->summary.push_back(std::string("Host state: ") +
                           status->Attribute("state"));

  /* ---- Host addresses (IP, MAC, IPID) ---- */
  for (XMLElement *addr = host->FirstChildElement("address"); addr;
       addr = addr->NextSiblingElement("address")) {
    if (const char *addr_str = addr->Attribute("addr")) {
      if (const char *addr_type = addr->Attribute("addrtype")) {
        std::string host_addr = std::string(addr_type) + ": " + addr_str;
        if (const char *vendor = addr->Attribute("vendor")) {
          host_addr += std::string(" (") + vendor + ")";
        }
        res->host_info.push_back(host_addr);
      }
    }
  }

  /* ---- Host names (reverse DNS) ---- */
  for (XMLElement *hostname = host->FirstChildElement("hostname"); hostname;
       hostname = hostname->NextSiblingElement("hostname")) {
    if (const char *name = hostname->Attribute("name")) {
      if (const char *type = hostname->Attribute("type")) {
        res->hostnames.push_back(std::string(type) + ": " + name);
      }
    }
  }

  /* ---- Ports ---- */
  XMLElement *ports = host->FirstChildElement("ports");
  if (!ports)
    return;

  std::set<std::string> os_set;
  std::set<std::string> cpe_set;

  for (XMLElement *p = ports->FirstChildElement("port"); p;
       p = p->NextSiblingElement("port")) {

    XMLElement *st = p->FirstChildElement("state");
    if (!st || std::string(st->Attribute("state")) != "open")
      continue;

    XMLElement *svc = p->FirstChildElement("service");
    std::string port_str = p->Attribute("portid");
    std::string protocol = p->Attribute("protocol");

    std::string row =
        port_str + "\t" + protocol +
        "\t" + (svc && svc->Attribute("name") ? svc->Attribute("name") : "") +
        "\t" +
        (svc && svc->Attribute("product") ? svc->Attribute("product") : "") +
        "\t" +
        (svc && svc->Attribute("version") ? svc->Attribute("version") : "");

    res->ports.push_back(row);

    /* ---- Port state details ---- */
    if (st) {
      std::string state_detail = "Port " + port_str + " [" + protocol + "] - State: " + st->Attribute("state");
      if (const char *reason = st->Attribute("reason")) {
        state_detail += ", Reason: " + std::string(reason);
      }
      if (const char *reason_ttl = st->Attribute("reason_ttl")) {
        state_detail += ", TTL: " + std::string(reason_ttl);
      }
      res->port_details.push_back(state_detail);
    }

    if (svc) {
      // Extract extra service information
      if (svc->Attribute("ostype")) {
        std::string os_str = svc->Attribute("ostype");
        os_set.insert(os_str);
        res->service_details.push_back("Port " + port_str + " - OS Type: " + os_str);
      }

      if (svc->Attribute("extrainfo")) {
        std::string extra = svc->Attribute("extrainfo");
        res->service_details.push_back("Port " + port_str + " - Extra Info: " + extra);
      }

      if (svc->Attribute("hostname")) {
        std::string hostname = svc->Attribute("hostname");
        res->service_details.push_back("Port " + port_str + " - Hostname: " + hostname);
      }

      if (svc->Attribute("tunnel")) {
        std::string tunnel = svc->Attribute("tunnel");
        res->service_details.push_back("Port " + port_str + " - Tunnel: " + tunnel);
      }

      if (svc->Attribute("conf")) {
        std::string conf = svc->Attribute("conf");
        res->service_details.push_back("Port " + port_str + " - Confidence: " + conf);
      }

      if (svc->Attribute("method")) {
        std::string method = svc->Attribute("method");
        res->service_details.push_back("Port " + port_str + " - Method: " + method);
      }

      if (svc->Attribute("ostype")) {
        res->os_detection.push_back(svc->Attribute("ostype"));
      }

      for (XMLElement *cpe = svc->FirstChildElement("cpe"); cpe;
           cpe = cpe->NextSiblingElement("cpe")) {
        if (cpe->GetText())
          cpe_set.insert(cpe->GetText());
      }
    }

    // Extract NSE script output
    for (XMLElement *script = p->FirstChildElement("script"); script;
         script = script->NextSiblingElement("script")) {
      if (const char *script_id = script->Attribute("id")) {
        if (const char *script_output = script->Attribute("output")) {
          std::string script_line = std::string("Port ") + port_str + " [" + script_id + "]: " + script_output;
          res->scripts_output.push_back(script_line);
        }
      }
    }
  }

  /* ---- OS Detection Matches (<osmatch> elements) ---- */
  for (XMLElement *osmatch = host->FirstChildElement("osmatch"); osmatch;
       osmatch = osmatch->NextSiblingElement("osmatch")) {
    if (const char *name = osmatch->Attribute("name")) {
      if (const char *accuracy = osmatch->Attribute("accuracy")) {
        std::string os_match = std::string(name) + " (Accuracy: " + accuracy + "%)";
        res->os_matches.push_back(os_match);
      }
    }

    // Extract OS classes within osmatch
    for (XMLElement *osclass = osmatch->FirstChildElement("osclass"); osclass;
         osclass = osclass->NextSiblingElement("osclass")) {
      std::string class_str;
      if (const char *type = osclass->Attribute("type"))
        class_str += std::string("Type: ") + type + " | ";
      if (const char *vendor = osclass->Attribute("vendor"))
        class_str += std::string("Vendor: ") + vendor + " | ";
      if (const char *osfamily = osclass->Attribute("osfamily"))
        class_str += std::string("Family: ") + osfamily + " | ";
      if (const char *osgen = osclass->Attribute("osgen"))
        class_str += std::string("Generation: ") + osgen + " | ";
      if (const char *accuracy = osclass->Attribute("accuracy"))
        class_str += std::string("Accuracy: ") + accuracy + "%";

      if (!class_str.empty()) {
        res->os_classes.push_back(class_str);
      }
    }
  }

  /* ---- Traceroute information ---- */
  XMLElement *trace = host->FirstChildElement("trace");
  if (trace) {
    res->traceroute_data.push_back("Traceroute:");
    for (XMLElement *hop = trace->FirstChildElement("hop"); hop;
         hop = hop->NextSiblingElement("hop")) {
      if (const char *ttl = hop->Attribute("ttl")) {
        std::string hop_str = std::string("  Hop ") + ttl + ": ";
        if (const char *host_name = hop->Attribute("host")) {
          hop_str += host_name;
        }
        if (const char *ip = hop->Attribute("ipaddr")) {
          hop_str += " (" + std::string(ip) + ")";
        }
        if (const char *rtt = hop->Attribute("rtt")) {
          hop_str += " - " + std::string(rtt) + "ms";
        }
        res->traceroute_data.push_back(hop_str);
      }
    }
  }

  /* ---- Service info tree (logical) ---- */
  if (!os_set.empty()) {
    res->service_tree.push_back("Operating Systems");
    for (auto &os : os_set)
      res->service_tree.push_back("  " + os);
  }

  if (!cpe_set.empty()) {
    res->service_tree.push_back("CPEs");
    for (auto &c : cpe_set)
      res->service_tree.push_back("  " + c);
  }
}
