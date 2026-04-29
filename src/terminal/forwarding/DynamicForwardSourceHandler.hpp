#ifndef __ET_DYNAMIC_FORWARD_SOURCE_HANDLER__
#define __ET_DYNAMIC_FORWARD_SOURCE_HANDLER__

#include "ForwardSourceHandler.hpp"
#include "Socks5Handshake.hpp"

namespace et {

/**
 * @brief Source handler for ssh-style `-D` dynamic forwarding.
 *
 * Behaves like a SOCKS5 server: listens on a TCP port locally, and for
 * each accepted connection runs a SOCKS5 handshake to learn the
 * client-requested destination. Once the destination is known the
 * handler emits a `PortForwardDestinationRequest` so the ET server
 * connects to that host:port on its end, exactly like a regular `-L`
 * forward — except the destination is dynamic per connection rather
 * than fixed at session-start time.
 *
 * The class extends ForwardSourceHandler and reuses its bookkeeping
 * (`socketFdMap`, `unassignedFds`) once a connection has finished its
 * handshake. The pre-handshake state is kept in this subclass: each
 * pending fd has its own `Socks5Handshake` parser plus a buffer for
 * any application-layer bytes that arrived in the same TCP segment as
 * the SOCKS request and must be flushed once the upstream socketId is
 * assigned.
 */
class DynamicForwardSourceHandler : public ForwardSourceHandler {
 public:
  DynamicForwardSourceHandler(shared_ptr<SocketHandler> _socketHandler,
                              const SocketEndpoint& _source);

  // Accept any pending TCP connections and start a SOCKS5 handshake for
  // each. Always returns -1 because dynamic forwards do not produce a
  // destination request at accept time — they wait for the SOCKS request
  // to identify the destination, which is surfaced via
  // `pollPendingRequests()` instead.
  int listen() override;

  void update(vector<PortForwardData>* data) override;

  void pollPendingRequests(
      vector<PortForwardDestinationRequest>* requests) override;

  bool hasUnassignedFd(int fd) override;
  void closeUnassignedFd(int fd) override;
  void addSocket(int socketId, int sourceFd) override;

  void getActiveFds(set<int>* fds) override;

 private:
  // SOCKS5 handshake state per fd that has been accepted but has not yet
  // produced a destination.
  struct PendingHandshake {
    Socks5Handshake parser;
    bool greetingReplied = false;
  };
  unordered_map<int, PendingHandshake> handshakes;

  // Destination requests queued by completed handshakes, drained by
  // pollPendingRequests().
  struct PendingRequest {
    int fd;
    SocketEndpoint destination;
  };
  vector<PendingRequest> pendingRequests;

  // Bytes the client pipelined behind the SOCKS request before we knew
  // the destination. Flushed as PORT_FORWARD_DATA once the socketId
  // arrives via addSocket().
  unordered_map<int, string> overflowBytes;

  // Helper: read bytes off `fd`, drive the handshake parser, send any
  // outbound replies, transition to upstream-pending or failure as
  // appropriate. Returns false if the fd should be removed from
  // `handshakes` (failure or transition completed).
  bool advanceHandshake(int fd, PendingHandshake& pending);

  void closeFd(int fd);
};

}  // namespace et
#endif  // __ET_DYNAMIC_FORWARD_SOURCE_HANDLER__
