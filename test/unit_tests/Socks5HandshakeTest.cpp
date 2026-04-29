#include "Socks5Handshake.hpp"
#include "TestHeaders.hpp"

using namespace et;

namespace {

// Helper: build the byte string [VER, NMETHODS, methods...].
string makeGreeting(std::initializer_list<unsigned char> methods) {
  string out;
  out.push_back(0x05);
  out.push_back(static_cast<char>(methods.size()));
  for (unsigned char m : methods) {
    out.push_back(static_cast<char>(m));
  }
  return out;
}

// Helper: build a CONNECT request.
//   atyp 0x01 -> 4-byte IPv4
//   atyp 0x03 -> length-prefixed domain
//   atyp 0x04 -> 16-byte IPv6
string makeConnectRequest(unsigned char atyp, const string& addrBytes,
                          uint16_t port) {
  string out;
  out.push_back(0x05);  // VER
  out.push_back(0x01);  // CMD = CONNECT
  out.push_back(0x00);  // RSV
  out.push_back(static_cast<char>(atyp));
  if (atyp == 0x03) {
    out.push_back(static_cast<char>(addrBytes.size()));
  }
  out.append(addrBytes);
  out.push_back(static_cast<char>((port >> 8) & 0xFF));
  out.push_back(static_cast<char>(port & 0xFF));
  return out;
}

}  // namespace

TEST_CASE("SOCKS5 happy path: greeting + CONNECT to a domain", "[Socks5]") {
  Socks5Handshake hs;

  hs.feed(makeGreeting({0x00}).data(), 3);
  REQUIRE(hs.getState() == Socks5Handshake::State::GreetingComplete);
  REQUIRE(hs.greetingReply() == string("\x05\x00", 2));

  hs.onGreetingReplySent();
  REQUIRE(hs.getState() == Socks5Handshake::State::AwaitRequest);

  string req = makeConnectRequest(0x03, "example.com", 8080);
  hs.feed(req.data(), req.size());
  REQUIRE(hs.getState() == Socks5Handshake::State::RequestComplete);
  REQUIRE(hs.getDestinationHost() == "example.com");
  REQUIRE(hs.getDestinationPort() == 8080);

  // Success reply: 10 bytes, leading 0x05 0x00 0x00 0x01.
  const string ok = hs.requestReply();
  REQUIRE(ok.size() == 10);
  REQUIRE(static_cast<unsigned char>(ok[0]) == 0x05);
  REQUIRE(static_cast<unsigned char>(ok[1]) == 0x00);
  REQUIRE(static_cast<unsigned char>(ok[3]) == 0x01);
}

TEST_CASE("SOCKS5 IPv4 destination round-trips dotted-quad", "[Socks5]") {
  Socks5Handshake hs;
  hs.feed(makeGreeting({0x00}).data(), 3);
  hs.onGreetingReplySent();

  string addr;
  addr.push_back(static_cast<char>(192));
  addr.push_back(static_cast<char>(168));
  addr.push_back(static_cast<char>(1));
  addr.push_back(static_cast<char>(10));
  string req = makeConnectRequest(0x01, addr, 22);
  hs.feed(req.data(), req.size());

  REQUIRE(hs.getState() == Socks5Handshake::State::RequestComplete);
  REQUIRE(hs.getDestinationHost() == "192.168.1.10");
  REQUIRE(hs.getDestinationPort() == 22);
}

TEST_CASE("SOCKS5 IPv6 destination is formatted as 8 hextets", "[Socks5]") {
  Socks5Handshake hs;
  hs.feed(makeGreeting({0x00}).data(), 3);
  hs.onGreetingReplySent();

  // ::1 -> 15 zero bytes followed by 0x01.
  string addr(16, '\0');
  addr[15] = 0x01;
  string req = makeConnectRequest(0x04, addr, 443);
  hs.feed(req.data(), req.size());

  REQUIRE(hs.getState() == Socks5Handshake::State::RequestComplete);
  // Long form is acceptable; getaddrinfo will normalise.
  REQUIRE(hs.getDestinationHost() == "0:0:0:0:0:0:0:1");
  REQUIRE(hs.getDestinationPort() == 443);
}

TEST_CASE("SOCKS5 byte-by-byte feed produces the same result", "[Socks5]") {
  Socks5Handshake hs;
  string greeting = makeGreeting({0x00, 0x02});  // no-auth + gssapi (ignored)
  for (char c : greeting) {
    hs.feed(&c, 1);
  }
  REQUIRE(hs.getState() == Socks5Handshake::State::GreetingComplete);
  hs.onGreetingReplySent();

  string req = makeConnectRequest(0x03, "host", 1234);
  for (char c : req) {
    hs.feed(&c, 1);
  }
  REQUIRE(hs.getState() == Socks5Handshake::State::RequestComplete);
  REQUIRE(hs.getDestinationHost() == "host");
  REQUIRE(hs.getDestinationPort() == 1234);
}

TEST_CASE("SOCKS5 rejects unsupported version", "[Socks5]") {
  Socks5Handshake hs;
  const char four[2] = {0x04, 0x01};
  hs.feed(four, 2);
  REQUIRE(hs.getState() == Socks5Handshake::State::Failed);
  REQUIRE_THAT(hs.lastError(), Catch::Matchers::ContainsSubstring("version"));
}

TEST_CASE("SOCKS5 rejects greeting without no-auth method", "[Socks5]") {
  Socks5Handshake hs;
  string g = makeGreeting({0x02});  // only username/password
  hs.feed(g.data(), g.size());
  REQUIRE(hs.getState() == Socks5Handshake::State::Failed);
  REQUIRE_THAT(hs.lastError(), Catch::Matchers::ContainsSubstring("no-auth"));
}

TEST_CASE("SOCKS5 rejects non-CONNECT command", "[Socks5]") {
  Socks5Handshake hs;
  hs.feed(makeGreeting({0x00}).data(), 3);
  hs.onGreetingReplySent();

  // CMD=0x02 (BIND) is unsupported.
  string req;
  req.push_back(0x05);
  req.push_back(0x02);
  req.push_back(0x00);
  req.push_back(0x01);
  req.append("\x7f\x00\x00\x01", 4);
  req.push_back(0x00);
  req.push_back(0x16);
  hs.feed(req.data(), req.size());
  REQUIRE(hs.getState() == Socks5Handshake::State::Failed);
  REQUIRE_THAT(hs.lastError(), Catch::Matchers::ContainsSubstring("CONNECT"));
}

TEST_CASE("SOCKS5 rejects zero destination port", "[Socks5]") {
  Socks5Handshake hs;
  hs.feed(makeGreeting({0x00}).data(), 3);
  hs.onGreetingReplySent();

  string req = makeConnectRequest(0x03, "example.com", 0);
  hs.feed(req.data(), req.size());
  REQUIRE(hs.getState() == Socks5Handshake::State::Failed);
  REQUIRE_THAT(hs.lastError(),
               Catch::Matchers::ContainsSubstring("zero destination port"));
}

TEST_CASE("SOCKS5 failure reply is well-formed", "[Socks5]") {
  const string fail = Socks5Handshake::requestFailureReply();
  REQUIRE(fail.size() == 10);
  REQUIRE(static_cast<unsigned char>(fail[0]) == 0x05);
  REQUIRE(static_cast<unsigned char>(fail[1]) == 0x01);  // general failure
  REQUIRE(static_cast<unsigned char>(fail[3]) == 0x01);  // ATYP IPv4
}
