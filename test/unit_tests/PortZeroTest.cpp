#include "ForwardSourceHandler.hpp"
#include "Headers.hpp"
#include "TcpSocketHandler.hpp"
#include "TestHeaders.hpp"

using namespace et;

namespace {

int querySockPort(int fd) {
  sockaddr_storage assigned;
  socklen_t alen = sizeof(assigned);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&assigned), &alen) != 0) {
    return -1;
  }
  if (assigned.ss_family == AF_INET) {
    return ntohs(reinterpret_cast<sockaddr_in*>(&assigned)->sin_port);
  }
  if (assigned.ss_family == AF_INET6) {
    return ntohs(reinterpret_cast<sockaddr_in6*>(&assigned)->sin6_port);
  }
  return -1;
}

}  // namespace

TEST_CASE("TcpSocketHandler::listen handles port=0 ephemeral binding",
          "[PortZero]") {
  TcpSocketHandler handler;

  SocketEndpoint endpoint;
  endpoint.set_name("127.0.0.1");
  endpoint.set_port(0);

  auto fds = handler.listen(endpoint);
  REQUIRE_FALSE(fds.empty());

  // The kernel should have assigned a real port on the underlying socket.
  const int assignedPort = querySockPort(*fds.begin());
  REQUIRE(assignedPort > 0);
  REQUIRE(assignedPort < 65536);

  // All bound fds in the set should share that port (so port=0 produces a
  // single user-facing port across address families).
  for (int fd : fds) {
    REQUIRE(querySockPort(fd) == assignedPort);
  }

  // Internal bookkeeping must be keyed by the assigned port, not by the
  // requested 0 — otherwise a follow-up port=0 call would falsely match.
  SocketEndpoint assignedEndpoint;
  assignedEndpoint.set_name("127.0.0.1");
  assignedEndpoint.set_port(assignedPort);
  auto storedFds = handler.getEndpointFds(assignedEndpoint);
  REQUIRE(storedFds == fds);

  handler.stopListening(assignedEndpoint);
}

TEST_CASE("PortForwardSourceResponse reports actual_port for port=0",
          "[PortZero]") {
  // ForwardSourceHandler should rewrite source.port() from 0 to the
  // OS-assigned port after listen(). PortForwardHandler::createSource then
  // surfaces it via PortForwardSourceResponse.actual_port.
  auto socketHandler = std::make_shared<TcpSocketHandler>();

  SocketEndpoint source;
  source.set_name("127.0.0.1");
  source.set_port(0);
  SocketEndpoint destination;
  destination.set_name("127.0.0.1");
  destination.set_port(80);

  ForwardSourceHandler fsh{socketHandler, source, destination};

  REQUIRE(fsh.getSource().has_port());
  REQUIRE(fsh.getSource().port() > 0);
  REQUIRE(fsh.getSource().port() < 65536);
}
