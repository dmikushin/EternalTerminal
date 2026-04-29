#ifndef __ET_TUNNEL_UTILS__
#define __ET_TUNNEL_UTILS__

#include "Headers.hpp"

namespace et {

/**
 * @brief Parses a comma-separated list of tunnel arguments into proto messages.
 *
 * When `gatewayPorts` is true, segments that do not specify an explicit bind
 * address default to "0.0.0.0" instead of "127.0.0.1". This mirrors the
 * effect of OpenSSH's `-g` option for local forwards.
 *
 * @throws TunnelParseException when the syntax is invalid.
 */
vector<PortForwardSourceRequest> parseRangesToRequests(
    const string& input, bool gatewayPorts = false);

vector<string> parseSshTunnelArg(const string& input);

/**
 * @brief Joins multiple tunnel argument strings (typically one per occurrence
 * of `-L`/`-R` on the command line) into a single comma-separated string
 * suitable for `parseRangesToRequests`. Empty entries are skipped so that the
 * result has no leading/trailing/repeated commas.
 */
string joinTunnelArgs(const vector<string>& parts);

/**
 * @brief Parses a comma-separated list of `-D`/`--dynamic-forward` arguments
 * into the listener endpoints to bind. Each argument is `[bind_address:]port`
 * (matching ssh -D); a port-only argument defaults the bind address to
 * 127.0.0.1 (or 0.0.0.0 when `gatewayPorts` is true). Bracketed IPv6
 * literals (`[::1]:1080`) and the `*:port` wildcard are accepted.
 *
 * @throws TunnelParseException on a malformed argument.
 */
vector<SocketEndpoint> parseDynamicForwardArgs(const string& input,
                                               bool gatewayPorts = false);

/**
 * @brief Thrown when an invalid tunnel source/destination string is
 * encountered.
 */
class TunnelParseException : public std::exception {
 public:
  explicit TunnelParseException(const string& msg) : message(msg) {}
  const char* what() const noexcept override { return message.c_str(); }

 private:
  std::string message = " ";
};

}  // namespace et
#endif  // __ET_TUNNEL_UTILS__
