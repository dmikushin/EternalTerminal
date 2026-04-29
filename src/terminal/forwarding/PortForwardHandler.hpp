#ifndef __PORT_FORWARD_HANDLER_H__
#define __PORT_FORWARD_HANDLER_H__

#include "Connection.hpp"
#include "ETerminal.pb.h"
#include "ForwardDestinationHandler.hpp"
#include "ForwardSourceHandler.hpp"
#include "SocketHandler.hpp"

namespace et {
/**
 * @brief Coordinates port forwarding requests, source/destination sockets, and
 * data flow.
 */
class PortForwardHandler {
 public:
  /** @brief Constructs forwarding helpers for network and router sockets. */
  explicit PortForwardHandler(shared_ptr<SocketHandler> _networkSocketHandler,
                              shared_ptr<SocketHandler> _pipeSocketHandler);
  /** @brief Polls all handlers for new destination/data and sends
   * `PortForwardData`. */
  void update(vector<PortForwardDestinationRequest>* requests,
              vector<PortForwardData>* dataToSend);
  /** @brief Handles control packets arriving over the SSH connection. */
  void handlePacket(const Packet& packet, shared_ptr<Connection> connection);
  PortForwardSourceResponse createSource(const PortForwardSourceRequest& pfsr,
                                         string* sourceName, uid_t userid,
                                         gid_t groupid);

  /**
   * @brief Brings up a dynamic (SOCKS5) forward listener bound to
   * `source`. Equivalent to `ssh -D [bind_address:]port`. Per-connection
   * destinations are extracted from the SOCKS5 handshake and translated
   * into ordinary `PortForwardDestinationRequest`s, so the server side
   * needs no changes.
   *
   * @return PortForwardSourceResponse with `actual_port` set to the
   * OS-assigned port (matters for `port=0` requests). `error` is set if
   * the listener could not be bound.
   */
  PortForwardSourceResponse createDynamicSource(const SocketEndpoint& source);
  /**
   * @brief Tears down the active source listener bound to `port` (the
   * actual OS-assigned port, not the original request value), closing
   * its accepted client sockets and stopping its listener.
   *
   * @return true if a matching source was found and removed; false if
   * no listener owns that port.
   */
  bool cancelSourceByPort(int port);
  /** @brief Creates a remote destination handler that forwards data to a user's
   * socket. */
  PortForwardDestinationResponse createDestination(
      const PortForwardDestinationRequest& pfdr);

  /** @brief Tears down the source socket associated with `fd`. */
  void closeSourceFd(int fd);
  /** @brief Tracks a new source socket using the provided logical identifier.
   */
  void addSourceSocketId(int socketId, int sourceFd);
  /** @brief Tears down the source socket tied to the socket ID. */
  void closeSourceSocketId(int socketId);
  /** @brief Sends data back to the listener that originally accepted the source
   * socket. */
  void sendDataToSourceOnSocket(int socketId, const string& data);
  void getForwardFds(set<int>* fds);

 protected:
  /** @brief Handler used for the SSH/network-facing sockets. */
  shared_ptr<SocketHandler> networkSocketHandler;
  /** @brief Handler used for the router/pipe-facing sockets. */
  shared_ptr<SocketHandler> pipeSocketHandler;
  /** @brief Active destination handlers keyed by socket id. */
  unordered_map<int, shared_ptr<ForwardDestinationHandler>> destinationHandlers;

  /** @brief Handlers for the listening port forward sources. */
  vector<shared_ptr<ForwardSourceHandler>> sourceHandlers;
  /** @brief Maps control socket IDs to their source handlers for routing data.
   */
  unordered_map<int, shared_ptr<ForwardSourceHandler>> socketIdSourceHandlerMap;
};
}  // namespace et

#endif  // __PORT_FORWARD_HANDLER_H__
