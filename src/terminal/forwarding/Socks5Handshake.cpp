#include "Socks5Handshake.hpp"

namespace et {

namespace {

constexpr unsigned char kVer = 0x05;
constexpr unsigned char kMethodNoAuth = 0x00;
constexpr unsigned char kMethodNoneAcceptable = 0xFF;
constexpr unsigned char kCmdConnect = 0x01;
constexpr unsigned char kAtypIpv4 = 0x01;
constexpr unsigned char kAtypDomain = 0x03;
constexpr unsigned char kAtypIpv6 = 0x04;

// Big-endian 16-bit read.
uint16_t readBE16(const unsigned char* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

// Format a numeric IPv4 byte array as a dotted-quad string.
string formatIpv4(const unsigned char* p) {
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
  return string(buf);
}

// Format 16 raw bytes of IPv6 in canonical-ish hex form. We deliberately do
// not collapse zero runs — the caller passes the result straight to
// getaddrinfo, which accepts the long form.
string formatIpv6(const unsigned char* p) {
  char buf[40];
  std::snprintf(buf, sizeof(buf), "%x:%x:%x:%x:%x:%x:%x:%x",
                static_cast<unsigned>(readBE16(p + 0)),
                static_cast<unsigned>(readBE16(p + 2)),
                static_cast<unsigned>(readBE16(p + 4)),
                static_cast<unsigned>(readBE16(p + 6)),
                static_cast<unsigned>(readBE16(p + 8)),
                static_cast<unsigned>(readBE16(p + 10)),
                static_cast<unsigned>(readBE16(p + 12)),
                static_cast<unsigned>(readBE16(p + 14)));
  return string(buf);
}

}  // namespace

void Socks5Handshake::feed(const char* data, size_t len) {
  if (state == State::Failed) return;
  buffer.append(data, len);
  advance();
}

void Socks5Handshake::onGreetingReplySent() {
  if (state == State::GreetingComplete) {
    state = State::AwaitRequest;
    advance();
  }
}

void Socks5Handshake::advance() {
  // Try to drain as many state transitions as available bytes allow.
  while (true) {
    if (state == State::AwaitGreeting) {
      if (!tryParseGreeting()) return;
    } else if (state == State::AwaitRequest) {
      if (!tryParseRequest()) return;
    } else {
      return;
    }
  }
}

bool Socks5Handshake::tryParseGreeting() {
  if (buffer.size() < 2) return false;
  const unsigned char* p =
      reinterpret_cast<const unsigned char*>(buffer.data());
  if (p[0] != kVer) {
    state = State::Failed;
    errorMessage = "SOCKS5: unsupported protocol version (only 5 is allowed)";
    return false;
  }
  const size_t nMethods = p[1];
  if (nMethods == 0) {
    state = State::Failed;
    errorMessage = "SOCKS5: greeting has zero methods";
    return false;
  }
  if (buffer.size() < 2 + nMethods) return false;

  // Look for METHOD 0x00 (no-auth) anywhere in the list.
  bool noAuthOffered = false;
  for (size_t i = 0; i < nMethods; ++i) {
    if (p[2 + i] == kMethodNoAuth) {
      noAuthOffered = true;
      break;
    }
  }
  if (!noAuthOffered) {
    state = State::Failed;
    errorMessage = "SOCKS5: client did not offer the no-auth method (0x00)";
    return false;
  }

  buffer.erase(0, 2 + nMethods);
  state = State::GreetingComplete;
  return false;  // Caller must call onGreetingReplySent() before we proceed.
}

bool Socks5Handshake::tryParseRequest() {
  if (buffer.size() < 4) return false;
  const unsigned char* p =
      reinterpret_cast<const unsigned char*>(buffer.data());
  if (p[0] != kVer) {
    state = State::Failed;
    errorMessage = "SOCKS5: unsupported request version";
    return false;
  }
  if (p[1] != kCmdConnect) {
    state = State::Failed;
    errorMessage = "SOCKS5: only the CONNECT command is supported";
    return false;
  }
  // p[2] is RSV, ignored.
  const unsigned char atyp = p[3];

  size_t addrStart = 4;
  size_t addrLen = 0;
  switch (atyp) {
    case kAtypIpv4:
      addrLen = 4;
      break;
    case kAtypIpv6:
      addrLen = 16;
      break;
    case kAtypDomain: {
      if (buffer.size() < 5) return false;
      const size_t domainLen = p[4];
      if (domainLen == 0) {
        state = State::Failed;
        errorMessage = "SOCKS5: empty domain name in request";
        return false;
      }
      addrStart = 5;
      addrLen = domainLen;
      break;
    }
    default:
      state = State::Failed;
      errorMessage = "SOCKS5: unsupported address type";
      return false;
  }

  const size_t totalLen = addrStart + addrLen + 2;  // + 2 bytes port
  if (buffer.size() < totalLen) return false;

  switch (atyp) {
    case kAtypIpv4:
      destinationHost = formatIpv4(p + addrStart);
      break;
    case kAtypIpv6:
      destinationHost = formatIpv6(p + addrStart);
      break;
    case kAtypDomain:
      destinationHost.assign(buffer.data() + addrStart, addrLen);
      break;
  }
  destinationPort = readBE16(p + addrStart + addrLen);
  if (destinationPort == 0) {
    state = State::Failed;
    errorMessage = "SOCKS5: zero destination port";
    return false;
  }

  buffer.erase(0, totalLen);
  state = State::RequestComplete;
  return true;
}

string Socks5Handshake::greetingReply() const {
  if (state == State::Failed) {
    char buf[2] = {static_cast<char>(kVer),
                   static_cast<char>(kMethodNoneAcceptable)};
    return string(buf, 2);
  }
  char buf[2] = {static_cast<char>(kVer), static_cast<char>(kMethodNoAuth)};
  return string(buf, 2);
}

string Socks5Handshake::requestReply() const {
  // VER=0x05 REP=0x00 RSV=0x00 ATYP=0x01 BND.ADDR=0.0.0.0 BND.PORT=0.
  // We do not attempt to surface the upstream bind info — the SOCKS
  // client doesn't depend on it for CONNECT.
  static const unsigned char success[10] = {0x05, 0x00, 0x00, 0x01, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x00};
  return string(reinterpret_cast<const char*>(success), sizeof(success));
}

string Socks5Handshake::requestFailureReply() {
  // VER=0x05 REP=0x01 (general failure) RSV=0x00 ATYP=0x01 BND...
  static const unsigned char failure[10] = {0x05, 0x01, 0x00, 0x01, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x00};
  return string(reinterpret_cast<const char*>(failure), sizeof(failure));
}

}  // namespace et
