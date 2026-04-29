#include "Headers.hpp"
#include "TestHeaders.hpp"
#include "TunnelUtils.hpp"

using namespace et;
using Catch::Matchers::ContainsSubstring;

TEST_CASE("Parses single port forward request", "[TunnelUtils]") {
  auto requests = parseRangesToRequests("1000:2000");

  REQUIRE(requests.size() == 1);
  REQUIRE(requests[0].has_source());
  REQUIRE(requests[0].source().name() == "127.0.0.1");
  REQUIRE(requests[0].source().port() == 1000);
  REQUIRE(requests[0].has_destination());
  REQUIRE(requests[0].destination().port() == 2000);
}

TEST_CASE("Parses matching port ranges", "[TunnelUtils]") {
  auto requests = parseRangesToRequests("8000-8002:9000-9002");

  REQUIRE(requests.size() == 3);
  for (int i = 0; i < 3; ++i) {
    INFO("Checking element " << i);
    REQUIRE(requests[i].has_source());
    REQUIRE(requests[i].source().port() == 8000 + i);
    REQUIRE(requests[i].has_destination());
    REQUIRE(requests[i].destination().port() == 9000 + i);
  }
}

TEST_CASE("Combo pair plus range", "[TunnelUtils]") {
  auto requests = parseRangesToRequests("1000:2000,8000-8002:9000-9002");

  REQUIRE(requests.size() == 4);

  REQUIRE(requests[0].has_source());
  REQUIRE(requests[0].source().name() == "127.0.0.1");
  REQUIRE(requests[0].source().port() == 1000);
  REQUIRE(requests[0].has_destination());
  REQUIRE(requests[0].destination().port() == 2000);
  for (int i = 1; i < 4; ++i) {
    INFO("Checking element " << i);
    REQUIRE(requests[i].has_source());
    REQUIRE(requests[i].source().port() == 8000 + i - 1);
    REQUIRE(requests[i].has_destination());
    REQUIRE(requests[i].destination().port() == 9000 + i - 1);
  }
}

TEST_CASE("Parses ssh style -L/-R arg", "[TunnelUtils]") {
  // ipv4
  auto ssh_parts = parseSshTunnelArg("localhost:8888:0.0.0.0:9999");
  REQUIRE(ssh_parts.size() == 4);
  REQUIRE(ssh_parts[0] == "localhost");
  REQUIRE(ssh_parts[1] == "8888");
  REQUIRE(ssh_parts[2] == "0.0.0.0");
  REQUIRE(ssh_parts[3] == "9999");

  // ipv6
  ssh_parts =
      parseSshTunnelArg("[::1]:8888:[2001:db8:85a3:0:0:8a2e:370:7334]:9999");
  REQUIRE(ssh_parts.size() == 4);
  REQUIRE(ssh_parts[0] == "::1");
  REQUIRE(ssh_parts[1] == "8888");
  REQUIRE(ssh_parts[2] == "2001:db8:85a3:0:0:8a2e:370:7334");
  REQUIRE(ssh_parts[3] == "9999");

  auto requests = parseRangesToRequests("localhost:8888:0.0.0.0:9999");

  REQUIRE(requests.size() == 1);
  REQUIRE(requests[0].has_source());
  REQUIRE(requests[0].source().name() == "localhost");
  REQUIRE(requests[0].source().port() == 8888);
  REQUIRE(requests[0].has_destination());
  REQUIRE(requests[0].destination().name() == "0.0.0.0");
  REQUIRE(requests[0].destination().port() == 9999);
}

TEST_CASE("Parses environment variable forward", "[TunnelUtils]") {
  auto requests = parseRangesToRequests("SSH_AUTH_SOCK:/tmp/agent.sock");

  REQUIRE(requests.size() == 1);
  REQUIRE(requests[0].has_environmentvariable());
  REQUIRE(requests[0].environmentvariable() == "SSH_AUTH_SOCK");
  REQUIRE(requests[0].has_destination());
  REQUIRE(requests[0].destination().name() == "/tmp/agent.sock");
  REQUIRE_FALSE(requests[0].has_source());
}

TEST_CASE("Rejects malformed port forward input", "[TunnelUtils]") {
  SECTION("Mismatched range lengths") {
    REQUIRE_THROWS_WITH(
        parseRangesToRequests("8000-8002:9000-9001"),
        ContainsSubstring("source/destination port range must have same"));
  }

  SECTION("Range paired with single port") {
    REQUIRE_THROWS_WITH(
        parseRangesToRequests("8000-8001:9000"),
        ContainsSubstring(
            "Invalid port range syntax: if source is a range, destination must "
            "be a range"));
  }

  SECTION("Non-numeric port") {
    try {
      parseRangesToRequests("abc:123");
      FAIL("Expected parseRangesToRequests to throw");
    } catch (const TunnelParseException& ex) {
      REQUIRE_THAT(ex.what(),
                   ContainsSubstring("Invalid tunnel argument 'abc:123'"));
    }
  }

  SECTION("Missing destination") {
    REQUIRE_THROWS_WITH(
        parseRangesToRequests("8080"),
        ContainsSubstring(
            "Tunnel argument must have source and destination between a ':'"));
  }

  SECTION("Ssh-style tunneling arg must use brackets for ipv6 addresses") {
    REQUIRE_THROWS_WITH(
        parseRangesToRequests("::1:8888:0.0.0.0:9999"),
        ContainsSubstring("Ipv6 addresses must be inside of square brackets"));
  }
}

TEST_CASE("Parses 3-field ssh-style port:host:hostport", "[TunnelUtils]") {
  SECTION("Single 3-field arg defaults bind to 127.0.0.1") {
    auto requests = parseRangesToRequests("8888:remote.example.com:9999");
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].has_source());
    REQUIRE(requests[0].source().name() == "127.0.0.1");
    REQUIRE(requests[0].source().port() == 8888);
    REQUIRE(requests[0].has_destination());
    REQUIRE(requests[0].destination().name() == "remote.example.com");
    REQUIRE(requests[0].destination().port() == 9999);
  }

  SECTION("3-field works with bracketed IPv6 destination") {
    auto requests = parseRangesToRequests("8888:[2001:db8::1]:9999");
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "127.0.0.1");
    REQUIRE(requests[0].source().port() == 8888);
    REQUIRE(requests[0].destination().name() == "2001:db8::1");
    REQUIRE(requests[0].destination().port() == 9999);
  }
}

TEST_CASE("Mixes ssh-style and et-style across comma list", "[TunnelUtils]") {
  // Previously the comma branch only accepted et-style; this test guards the
  // unified per-segment dispatcher.
  auto requests = parseRangesToRequests(
      "1000:2000,8888:remote:80,[::1]:9000:dst.example:443");

  REQUIRE(requests.size() == 3);

  REQUIRE(requests[0].source().name() == "127.0.0.1");
  REQUIRE(requests[0].source().port() == 1000);
  REQUIRE(requests[0].destination().port() == 2000);

  REQUIRE(requests[1].source().name() == "127.0.0.1");
  REQUIRE(requests[1].source().port() == 8888);
  REQUIRE(requests[1].destination().name() == "remote");
  REQUIRE(requests[1].destination().port() == 80);

  REQUIRE(requests[2].source().name() == "::1");
  REQUIRE(requests[2].source().port() == 9000);
  REQUIRE(requests[2].destination().name() == "dst.example");
  REQUIRE(requests[2].destination().port() == 443);
}

TEST_CASE("Joins tunnel args from multiple -L/-R occurrences",
          "[TunnelUtils]") {
  SECTION("Empty input yields empty string") {
    REQUIRE(joinTunnelArgs({}) == "");
  }

  SECTION("Single value passes through unchanged") {
    REQUIRE(joinTunnelArgs({"1000:2000"}) == "1000:2000");
  }

  SECTION("Multiple values are joined by commas") {
    REQUIRE(joinTunnelArgs({"1000:2000", "3000:4000"}) ==
            "1000:2000,3000:4000");
  }

  SECTION("Values that already contain commas are preserved") {
    REQUIRE(joinTunnelArgs({"1000:2000,3000:4000", "5000:6000"}) ==
            "1000:2000,3000:4000,5000:6000");
  }

  SECTION("Empty entries are skipped without producing repeated commas") {
    REQUIRE(joinTunnelArgs({"", "1000:2000", "", "3000:4000", ""}) ==
            "1000:2000,3000:4000");
  }

  SECTION("Joined output round-trips through parseRangesToRequests") {
    auto joined = joinTunnelArgs({"1000:2000", "3000:4000"});
    auto requests = parseRangesToRequests(joined);
    REQUIRE(requests.size() == 2);
    REQUIRE(requests[0].source().port() == 1000);
    REQUIRE(requests[0].destination().port() == 2000);
    REQUIRE(requests[1].source().port() == 3000);
    REQUIRE(requests[1].destination().port() == 4000);
  }
}

TEST_CASE("Recognizes wildcard bind in 4-field ssh-style", "[TunnelUtils]") {
  SECTION("Asterisk bind expands to 0.0.0.0") {
    auto requests = parseRangesToRequests("*:8080:host:80");
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "0.0.0.0");
    REQUIRE(requests[0].source().port() == 8080);
  }

  SECTION("Empty bind expands to 0.0.0.0") {
    auto requests = parseRangesToRequests(":8080:host:80");
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "0.0.0.0");
    REQUIRE(requests[0].source().port() == 8080);
  }

  SECTION("Explicit 127.0.0.1 bind is preserved as-is") {
    auto requests = parseRangesToRequests("127.0.0.1:8080:host:80");
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "127.0.0.1");
  }
}

TEST_CASE("gatewayPorts flag rewrites default loopback bind", "[TunnelUtils]") {
  SECTION("Et-style pair switches default to 0.0.0.0 with gateway-ports") {
    auto requests = parseRangesToRequests("8080:80", /*gatewayPorts=*/true);
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "0.0.0.0");
    REQUIRE(requests[0].source().port() == 8080);
  }

  SECTION("Et-style range switches default to 0.0.0.0 with gateway-ports") {
    auto requests =
        parseRangesToRequests("8000-8001:9000-9001", /*gatewayPorts=*/true);
    REQUIRE(requests.size() == 2);
    for (auto& r : requests) {
      REQUIRE(r.source().name() == "0.0.0.0");
    }
  }

  SECTION("3-field ssh-style switches default to 0.0.0.0 with gateway-ports") {
    auto requests =
        parseRangesToRequests("8080:host:80", /*gatewayPorts=*/true);
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "0.0.0.0");
  }

  SECTION("4-field ssh-style with explicit bind ignores gateway-ports flag") {
    auto requests = parseRangesToRequests("127.0.0.1:8080:host:80",
                                          /*gatewayPorts=*/true);
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "127.0.0.1");
  }

  SECTION("Without gateway-ports the default stays 127.0.0.1") {
    auto requests = parseRangesToRequests("8080:80");
    REQUIRE(requests[0].source().name() == "127.0.0.1");
  }
}

TEST_CASE("Parses ssh-style UNIX-domain socket forwards", "[TunnelUtils]") {
  SECTION("local_socket:remote_socket - both UNIX") {
    auto requests = parseRangesToRequests("/tmp/local.sock:/tmp/remote.sock");
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].has_source());
    REQUIRE(requests[0].source().name() == "/tmp/local.sock");
    REQUIRE_FALSE(requests[0].source().has_port());
    REQUIRE(requests[0].has_destination());
    REQUIRE(requests[0].destination().name() == "/tmp/remote.sock");
    REQUIRE_FALSE(requests[0].destination().has_port());
  }

  SECTION("port:remote_socket - TCP listen, UNIX destination") {
    auto requests = parseRangesToRequests("8080:/tmp/remote.sock");
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "127.0.0.1");
    REQUIRE(requests[0].source().port() == 8080);
    REQUIRE(requests[0].destination().name() == "/tmp/remote.sock");
    REQUIRE_FALSE(requests[0].destination().has_port());
  }

  SECTION("bind:port:remote_socket - explicit bind, UNIX destination") {
    auto requests = parseRangesToRequests("0.0.0.0:8080:/tmp/remote.sock");
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "0.0.0.0");
    REQUIRE(requests[0].source().port() == 8080);
    REQUIRE(requests[0].destination().name() == "/tmp/remote.sock");
    REQUIRE_FALSE(requests[0].destination().has_port());
  }

  SECTION("local_socket:host:hostport - UNIX listen, TCP destination") {
    auto requests = parseRangesToRequests("/tmp/local.sock:host.example:80");
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "/tmp/local.sock");
    REQUIRE_FALSE(requests[0].source().has_port());
    REQUIRE(requests[0].destination().name() == "host.example");
    REQUIRE(requests[0].destination().port() == 80);
  }

  SECTION("Mixing UNIX and TCP forwards in a comma list") {
    auto requests =
        parseRangesToRequests("8080:80,/tmp/a.sock:/tmp/b.sock,9090:host:443");
    REQUIRE(requests.size() == 3);
    // 8080:80 -> et-style TCP pair
    REQUIRE(requests[0].source().name() == "127.0.0.1");
    REQUIRE(requests[0].source().port() == 8080);
    REQUIRE(requests[0].destination().port() == 80);
    REQUIRE_FALSE(requests[0].destination().has_name());
    // /tmp/a.sock:/tmp/b.sock -> UNIX -> UNIX
    REQUIRE(requests[1].source().name() == "/tmp/a.sock");
    REQUIRE_FALSE(requests[1].source().has_port());
    REQUIRE(requests[1].destination().name() == "/tmp/b.sock");
    REQUIRE_FALSE(requests[1].destination().has_port());
    // 9090:host:443 -> 3-field TCP -> TCP
    REQUIRE(requests[2].source().name() == "127.0.0.1");
    REQUIRE(requests[2].source().port() == 9090);
    REQUIRE(requests[2].destination().name() == "host");
    REQUIRE(requests[2].destination().port() == 443);
  }

  SECTION("gateway-ports propagates to TCP-to-UNIX forwards") {
    auto requests =
        parseRangesToRequests("8080:/tmp/remote.sock", /*gatewayPorts=*/true);
    REQUIRE(requests.size() == 1);
    REQUIRE(requests[0].source().name() == "0.0.0.0");
    REQUIRE(requests[0].source().port() == 8080);
  }

  SECTION("env-var pipe still recognized when destination is a path") {
    // SSH_AUTH_SOCK is not a UNIX path (no leading '/'), so this stays an
    // environment-variable pipe forward, not a UNIX-to-UNIX bridge.
    auto requests = parseRangesToRequests("SSH_AUTH_SOCK:/tmp/agent.sock");
    REQUIRE(requests.size() == 1);
    REQUIRE_FALSE(requests[0].has_source());
    REQUIRE(requests[0].environmentvariable() == "SSH_AUTH_SOCK");
    REQUIRE(requests[0].destination().name() == "/tmp/agent.sock");
  }
}

TEST_CASE("Generates random alphanumeric strings", "[genRandomAlphaNum]") {
  constexpr int desiredLength = 16;
  const string allowedChars =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  auto token = genRandomAlphaNum(desiredLength);

  REQUIRE(token.size() == desiredLength);
  for (char c : token) {
    REQUIRE(allowedChars.find(c) != string::npos);
  }
}
