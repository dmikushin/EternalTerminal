#include "TunnelUtils.hpp"

namespace et {

namespace {

// Tokenize a tunnel argument by ':' while keeping anything inside [] intact,
// so that bracketed IPv6 addresses survive splitting. No size validation —
// callers decide what part counts they accept.
vector<string> splitTunnelByColon(const string& input) {
  bool inBrackets = false;
  string currentPart;
  vector<string> parts;
  for (char c : input) {
    if (c == '[') {
      inBrackets = true;
    } else if (c == ']') {
      inBrackets = false;
    } else if (c == ':' && !inBrackets) {
      parts.push_back(currentPart);
      currentPart.clear();
    } else {
      currentPart += c;
    }
  }
  parts.push_back(currentPart);
  return parts;
}

// True when `s` consists entirely of digits and dashes (a port number or a
// `start-end` range). Used to disambiguate the 2-part case between an
// et-style port pair and an environment-variable pipe like
// `SSH_AUTH_SOCK:/tmp/agent.sock`.
bool looksNumericOrRange(const string& s) {
  return !s.empty() && s.find_first_not_of("0123456789-") == string::npos;
}

void emitEnvVarPipe(vector<PortForwardSourceRequest>& pfsrs,
                    const vector<string>& parts) {
  // Forwarding named pipes via environment variables (e.g. SSH_AUTH_SOCK).
  PortForwardSourceRequest pfsr;
  pfsr.set_environmentvariable(parts[0]);
  pfsr.mutable_destination()->set_name(parts[1]);
  pfsrs.push_back(pfsr);
}

void emitEtStylePair(vector<PortForwardSourceRequest>& pfsrs,
                     const vector<string>& parts, const string& fullInput,
                     bool gatewayPorts) {
  const string& src = parts[0];
  const string& dst = parts[1];
  const bool srcRange = src.find('-') != string::npos;
  const bool dstRange = dst.find('-') != string::npos;
  const string defaultBind = gatewayPorts ? "0.0.0.0" : "127.0.0.1";
  try {
    if (srcRange && dstRange) {
      auto srcRangeParts = split(src, '-');
      const int srcStart = stoi(srcRangeParts[0]);
      const int srcEnd = stoi(srcRangeParts[1]);
      auto dstRangeParts = split(dst, '-');
      const int dstStart = stoi(dstRangeParts[0]);
      const int dstEnd = stoi(dstRangeParts[1]);
      if (srcEnd - srcStart != dstEnd - dstStart) {
        throw TunnelParseException(
            "source/destination port range must have same length");
      }
      const int len = srcEnd - srcStart + 1;
      for (int i = 0; i < len; ++i) {
        PortForwardSourceRequest pfsr;
        pfsr.mutable_source()->set_name(defaultBind);
        pfsr.mutable_source()->set_port(srcStart + i);
        pfsr.mutable_destination()->set_port(dstStart + i);
        pfsrs.push_back(pfsr);
      }
    } else if (srcRange || dstRange) {
      throw TunnelParseException(
          "Invalid port range syntax: if source is a range, "
          "destination must be a range (and vice versa)");
    } else {
      PortForwardSourceRequest pfsr;
      pfsr.mutable_source()->set_name(defaultBind);
      pfsr.mutable_source()->set_port(stoi(src));
      pfsr.mutable_destination()->set_port(stoi(dst));
      pfsrs.push_back(pfsr);
    }
  } catch (const TunnelParseException&) {
    throw;
  } catch (const std::logic_error& lr) {
    throw TunnelParseException("Invalid tunnel argument '" + fullInput +
                               "': " + lr.what());
  }
}

void emitSsh3Field(vector<PortForwardSourceRequest>& pfsrs,
                   const vector<string>& parts, const string& fullInput,
                   bool gatewayPorts) {
  // ssh-style: port:host:hostport. Default bind is 127.0.0.1, matching
  // OpenSSH without GatewayPorts; with `-g` it switches to 0.0.0.0.
  try {
    PortForwardSourceRequest pfsr;
    pfsr.mutable_source()->set_name(gatewayPorts ? "0.0.0.0" : "127.0.0.1");
    pfsr.mutable_source()->set_port(stoi(parts[0]));
    pfsr.mutable_destination()->set_name(parts[1]);
    pfsr.mutable_destination()->set_port(stoi(parts[2]));
    pfsrs.push_back(pfsr);
  } catch (const std::logic_error& lr) {
    throw TunnelParseException("Invalid tunnel argument '" + fullInput +
                               "': " + lr.what());
  }
}

void emitSsh4Field(vector<PortForwardSourceRequest>& pfsrs,
                   const vector<string>& parts, const string& fullInput) {
  // ssh-style: bind_address:port:host:hostport.
  // Per ssh(1): an empty bind_address or "*" indicates that the port
  // should be available from all interfaces.
  try {
    PortForwardSourceRequest pfsr;
    const string& bind = parts[0];
    if (bind.empty() || bind == "*") {
      pfsr.mutable_source()->set_name("0.0.0.0");
    } else {
      pfsr.mutable_source()->set_name(bind);
    }
    pfsr.mutable_source()->set_port(stoi(parts[1]));
    pfsr.mutable_destination()->set_name(parts[2]);
    pfsr.mutable_destination()->set_port(stoi(parts[3]));
    pfsrs.push_back(pfsr);
  } catch (const std::logic_error& lr) {
    throw TunnelParseException("Invalid tunnel argument '" + fullInput +
                               "': " + lr.what());
  }
}

// Parse a single tunnel-arg segment (no commas inside) and append the
// resulting requests to `pfsrs`. Dispatches by the number of colon-separated
// parts (respecting bracketed IPv6 groups). When `gatewayPorts` is true,
// segments without an explicit bind address default to 0.0.0.0 instead of
// 127.0.0.1.
void parseOneTunnelArg(vector<PortForwardSourceRequest>& pfsrs,
                       const string& segment, bool gatewayPorts) {
  auto parts = splitTunnelByColon(segment);
  switch (parts.size()) {
    case 0:
    case 1:
      throw TunnelParseException(
          "Tunnel argument must have source and destination between a ':'");
    case 2: {
      const bool srcNumish = looksNumericOrRange(parts[0]);
      const bool dstNumish = looksNumericOrRange(parts[1]);
      if (!srcNumish && !dstNumish) {
        emitEnvVarPipe(pfsrs, parts);
      } else {
        emitEtStylePair(pfsrs, parts, segment, gatewayPorts);
      }
      break;
    }
    case 3:
      emitSsh3Field(pfsrs, parts, segment, gatewayPorts);
      break;
    case 4:
      emitSsh4Field(pfsrs, parts, segment);
      break;
    default:
      throw TunnelParseException(
          "Ipv6 addresses must be inside of square brackets, ie "
          "[::1]:8080:[::]:9090");
  }
}

}  // namespace

// Public: tokenize an ssh-style tunnel arg, requiring exactly 4 parts.
// Used by callers that already know they have a 4-field ssh-style argument.
vector<string> parseSshTunnelArg(const string& input) {
  auto parts = splitTunnelByColon(input);
  if (parts.size() < 4) {
    throw TunnelParseException(
        "The 4 part ssh-style tunneling arg (bind_address:port:host:hostport) "
        "must be supplied.");
  }
  if (parts.size() > 4) {
    throw TunnelParseException(
        "Ipv6 addresses must be inside of square brackets, ie "
        "[::1]:8080:[::]:9090");
  }
  return parts;
}

vector<PortForwardSourceRequest> parseRangesToRequests(const string& input,
                                                       bool gatewayPorts) {
  vector<PortForwardSourceRequest> pfsrs;
  for (auto& segment : split(input, ',')) {
    parseOneTunnelArg(pfsrs, segment, gatewayPorts);
  }
  return pfsrs;
}

string joinTunnelArgs(const vector<string>& parts) {
  string joined;
  for (const auto& part : parts) {
    if (part.empty()) continue;
    if (!joined.empty()) joined += ",";
    joined += part;
  }
  return joined;
}

}  // namespace et
