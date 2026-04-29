#ifndef __FORWARD_SOURCE_HANDLER_H__
#define __FORWARD_SOURCE_HANDLER_H__

#include "Headers.hpp"
#include "SocketHandler.hpp"

namespace et {
/**
 * @brief Accepts incoming connections on a local endpoint and tracks open
 * sockets.
 */
class ForwardSourceHandler {
 public:
  /** @brief Creates source/destination handlers used for local port forwarding.
   */
  ForwardSourceHandler(shared_ptr<SocketHandler> _socketHandler,
                       const SocketEndpoint& _source,
                       const SocketEndpoint& _destination);

  virtual ~ForwardSourceHandler();

  /** @brief Starts listening on the source endpoint and returns the server fd.
   */
  virtual int listen();

  /** @brief Polls all active sockets and stages `PortForwardData` for
   * destinations. */
  virtual void update(vector<PortForwardData>* data);

  /** @brief Lets dynamic-forward subclasses surface deferred
   * `PortForwardDestinationRequest`s once they have, e.g., completed a
   * SOCKS handshake on a freshly-accepted connection. The base
   * (static-forward) implementation does nothing because static
   * forwards emit their request synchronously from `listen()`.
   */
  virtual void pollPendingRequests(
      vector<PortForwardDestinationRequest>* /*requests*/) {}

  /** @brief Returns true if an accepted socket is pending assignment. */
  virtual bool hasUnassignedFd(int fd);

  /** @brief Closes sockets that were accepted but not yet assigned an ID. */
  virtual void closeUnassignedFd(int fd);

  /** @brief Maps a socketId (from the control channel) to a pending fd. */
  virtual void addSocket(int socketId, int sourceFd);

  /** @brief Closes the socket mapped to `socketId`. */
  virtual void closeSocket(int socketId);

  /** @brief Sends bytes from the remote side down the local source socket. */
  virtual void sendDataOnSocket(int socketId, const string& data);

  virtual void getActiveFds(set<int>* fds);

  inline SocketEndpoint getDestination() { return destination; }

  /**
   * @brief Returns the source endpoint actually bound by the handler. For
   * requests that asked for port=0 this reflects the OS-assigned port,
   * not the original 0.
   */
  inline const SocketEndpoint& getSource() const { return source; }

  /**
   * @brief Closes every accepted (or pending-assignment) client socket.
   * Used when the user cancels a forward via `~C -KL`/`~C -KR`: the
   * listener is taken down by the destructor, but in-flight connections
   * are owned here and must be closed explicitly.
   */
  void closeAcceptedSockets();

 protected:
  /** @brief Socket helper used to accept connections on the source endpoint. */
  shared_ptr<SocketHandler> socketHandler;
  /** @brief Local endpoint clients connect to for port forwarding. */
  SocketEndpoint source;
  /** @brief Remote destination endpoint that receives forwarded data. */
  SocketEndpoint destination;
  /** @brief Sockets that are awaiting assignment from the control stream. */
  unordered_set<int> unassignedFds;
  /** @brief Maps logical socket IDs to their accepted file descriptors. */
  unordered_map<int, int> socketFdMap;
};
}  // namespace et

#endif  // __FORWARD_SOURCE_HANDLER_H__
