#ifndef __ET_SOCKS5_HANDSHAKE__
#define __ET_SOCKS5_HANDSHAKE__

#include "Headers.hpp"

namespace et {

/**
 * @brief Incremental SOCKS5 server-side handshake parser.
 *
 * Drives a small state machine over bytes received on an accepted client
 * socket. The caller feeds raw bytes via `feed()`, queries the current
 * state, and at the appropriate transitions sends the corresponding
 * reply (greetingReply, requestReply) back to the client.
 *
 * Only the SOCKS5 CONNECT command is supported (no BIND, no UDP
 * ASSOCIATE) — that is exactly the subset OpenSSH uses for `-D`. Both
 * IPv4, IPv6 and domain-name destination atoms are accepted.
 *
 * Authentication: the parser advertises support for METHOD 0x00 (no
 * auth). If the client's greeting does not list 0x00 the parser fails
 * the handshake and surfaces an error string; the caller should send
 * `\x05\xFF` and close the socket.
 */
class Socks5Handshake {
 public:
  enum class State {
    AwaitGreeting,     // Buffering bytes for [VER, NMETHODS, METHODS...].
    GreetingComplete,  // Caller should send greetingReply() now.
    AwaitRequest,      // Buffering bytes for the CONNECT request.
    RequestComplete,   // Destination resolved; send requestReply() and
                       // start tunneling.
    Failed,            // Unrecoverable protocol error; see lastError().
  };

  Socks5Handshake() = default;

  /**
   * @brief Feed `len` bytes to the parser. May advance the state by zero
   * or more transitions. After call, inspect getState() to decide what
   * to do next.
   */
  void feed(const char* data, size_t len);

  State getState() const { return state; }
  const string& lastError() const { return errorMessage; }

  /**
   * @brief Mark the greeting reply as having been sent so the parser
   * begins consuming the request bytes. Call this after writing
   * greetingReply() to the socket.
   */
  void onGreetingReplySent();

  /**
   * @brief Reply to the client's METHOD selection: VER=0x05, METHOD=0x00.
   */
  string greetingReply() const;

  /**
   * @brief Reply to the CONNECT request reporting success and a dummy
   * BND.ADDR/BND.PORT (the upstream side is opaque to the SOCKS client).
   */
  string requestReply() const;

  /**
   * @brief Reply to the CONNECT request reporting a generic failure.
   * The parser does not produce this on its own — the higher layer
   * calls it when the upstream connection cannot be established.
   */
  static string requestFailureReply();

  /** @brief Resolved destination host. Only valid after RequestComplete. */
  const string& getDestinationHost() const { return destinationHost; }

  /** @brief Resolved destination port. Only valid after RequestComplete. */
  int getDestinationPort() const { return destinationPort; }

 private:
  void advance();
  bool tryParseGreeting();
  bool tryParseRequest();

  State state = State::AwaitGreeting;
  string buffer;
  string errorMessage;
  string destinationHost;
  int destinationPort = 0;
};

}  // namespace et
#endif  // __ET_SOCKS5_HANDSHAKE__
