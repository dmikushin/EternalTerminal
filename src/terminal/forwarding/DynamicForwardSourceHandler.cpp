#include "DynamicForwardSourceHandler.hpp"

namespace et {

namespace {

// Empty SocketEndpoint passed to the base ctor. The base captures it as
// `destination` but we never consult that field for dynamic forwards;
// every connection learns its destination from the SOCKS handshake.
SocketEndpoint emptyEndpoint() { return SocketEndpoint(); }

void writeAllBest(SocketHandler& handler, int fd, const string& bytes) {
  if (bytes.empty()) return;
  handler.writeAllOrReturn(fd, bytes.data(), bytes.size());
}

}  // namespace

DynamicForwardSourceHandler::DynamicForwardSourceHandler(
    shared_ptr<SocketHandler> _socketHandler, const SocketEndpoint& _source)
    : ForwardSourceHandler(_socketHandler, _source, emptyEndpoint()) {}

int DynamicForwardSourceHandler::listen() {
  // Drain every fd currently ready to accept; each one starts its own
  // SOCKS handshake. Always return -1 so PortForwardHandler does not
  // try to emit a destination request with a static (and meaningless)
  // destination.
  for (int listenerFd : socketHandler->getEndpointFds(source)) {
    while (true) {
      int fd = socketHandler->accept(listenerFd);
      if (fd < 0) break;
      LOG(INFO) << "Dynamic forward " << source << " accepted fd " << fd
                << "; awaiting SOCKS5 handshake";
      handshakes.emplace(fd, PendingHandshake{});
    }
  }
  return -1;
}

bool DynamicForwardSourceHandler::advanceHandshake(int fd,
                                                   PendingHandshake& pending) {
  // Read whatever the client has sent so far and feed it to the parser.
  while (socketHandler->hasData(fd)) {
    char buf[1024];
    int n = socketHandler->read(fd, buf, sizeof(buf));
    auto savedErrno = GetErrno();
    if (n <= 0) {
      if (n == -1 && (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK)) {
        break;
      }
      LOG(INFO) << "Dynamic forward fd " << fd << " closed during handshake";
      closeFd(fd);
      return false;
    }
    pending.parser.feed(buf, static_cast<size_t>(n));
    if (pending.parser.getState() == Socks5Handshake::State::Failed) {
      LOG(WARNING) << "SOCKS5 handshake on fd " << fd
                   << " failed: " << pending.parser.lastError();
      writeAllBest(*socketHandler, fd, pending.parser.greetingReply());
      closeFd(fd);
      return false;
    }
    if (pending.parser.getState() == Socks5Handshake::State::GreetingComplete &&
        !pending.greetingReplied) {
      writeAllBest(*socketHandler, fd, pending.parser.greetingReply());
      pending.greetingReplied = true;
      pending.parser.onGreetingReplySent();
    }
    if (pending.parser.getState() == Socks5Handshake::State::RequestComplete) {
      // Send the success reply, capture the destination, and hand the
      // fd off to the base unassigned-fds bookkeeping. PortForwardHandler
      // will pick it up via pollPendingRequests() and emit a
      // PORT_FORWARD_DESTINATION_REQUEST.
      writeAllBest(*socketHandler, fd, pending.parser.requestReply());

      SocketEndpoint dest;
      dest.set_name(pending.parser.getDestinationHost());
      dest.set_port(pending.parser.getDestinationPort());
      pendingRequests.push_back({fd, dest});
      unassignedFds.insert(fd);
      LOG(INFO) << "SOCKS5 handshake on fd " << fd << " resolved to "
                << dest.name() << ":" << dest.port();
      // Note: the parser's internal buffer may still hold bytes the
      // client pipelined after the SOCKS request. Stash them so we can
      // flush once the socketId is assigned by the server.
      // (Socks5Handshake clears its buffer as it consumes; anything
      //  beyond RequestComplete remains.)
      // We currently do not surface the parser's leftover bytes
      // because the parser implementation drops them after parsing.
      // For pipelined clients we'd extend the parser API; for now,
      // most SOCKS clients wait for our reply before sending data.
      return false;
    }
  }
  return true;
}

void DynamicForwardSourceHandler::update(vector<PortForwardData>* data) {
  // Advance every in-flight handshake. Drop the entry from `handshakes`
  // when it transitions out (either failed and closed, or moved to
  // unassignedFds via the base bookkeeping).
  for (auto it = handshakes.begin(); it != handshakes.end();) {
    if (advanceHandshake(it->first, it->second)) {
      ++it;
    } else {
      it = handshakes.erase(it);
    }
  }

  // Flush any pipelined bytes captured before the socketId was known.
  // (Currently always empty; reserved for a future parser revision.)
  for (auto it = overflowBytes.begin(); it != overflowBytes.end();) {
    int fd = it->first;
    bool flushed = false;
    for (auto& kv : socketFdMap) {
      if (kv.second == fd) {
        PortForwardData pwd;
        pwd.set_socketid(kv.first);
        pwd.set_sourcetodestination(true);
        pwd.set_buffer(it->second);
        data->push_back(pwd);
        flushed = true;
        break;
      }
    }
    if (flushed) {
      it = overflowBytes.erase(it);
    } else {
      ++it;
    }
  }

  // Pump established sockets via the base implementation.
  ForwardSourceHandler::update(data);
}

void DynamicForwardSourceHandler::pollPendingRequests(
    vector<PortForwardDestinationRequest>* requests) {
  for (auto& pending : pendingRequests) {
    PortForwardDestinationRequest req;
    *(req.mutable_destination()) = pending.destination;
    req.set_fd(pending.fd);
    requests->push_back(req);
  }
  pendingRequests.clear();
}

bool DynamicForwardSourceHandler::hasUnassignedFd(int fd) {
  // Only fds that finished SOCKS handshake should be matched against
  // server replies. Fds still in the handshake phase are owned by us
  // and must not be paired with a socketId.
  return ForwardSourceHandler::hasUnassignedFd(fd);
}

void DynamicForwardSourceHandler::closeUnassignedFd(int fd) {
  ForwardSourceHandler::closeUnassignedFd(fd);
}

void DynamicForwardSourceHandler::addSocket(int socketId, int sourceFd) {
  ForwardSourceHandler::addSocket(socketId, sourceFd);
}

void DynamicForwardSourceHandler::getActiveFds(set<int>* fds) {
  ForwardSourceHandler::getActiveFds(fds);
  for (auto& kv : handshakes) {
    fds->insert(kv.first);
  }
}

void DynamicForwardSourceHandler::closeFd(int fd) {
  socketHandler->close(fd);
  overflowBytes.erase(fd);
  unassignedFds.erase(fd);
}

}  // namespace et
