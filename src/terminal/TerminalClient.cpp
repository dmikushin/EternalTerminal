#include "TerminalClient.hpp"

#include "EscapeProcessor.hpp"
#include "TelemetryService.hpp"
#include "TunnelUtils.hpp"

namespace et {

TerminalClient::TerminalClient(shared_ptr<SocketHandler> _socketHandler,
                               shared_ptr<SocketHandler> _pipeSocketHandler,
                               const SocketEndpoint& _socketEndpoint,
                               const string& id, const string& passkey,
                               shared_ptr<Console> _console, bool jumphost,
                               const string& tunnels,
                               const string& reverseTunnels, bool gatewayPorts,
                               bool exitOnForwardFailure, bool forwardSshAgent,
                               const string& identityAgent,
                               int _keepaliveDuration,
                               const vector<pair<string, string>>& envVars)
    : console(_console),
      shuttingDown(false),
      keepaliveDuration(_keepaliveDuration),
      gatewayPorts(gatewayPorts) {
  portForwardHandler = shared_ptr<PortForwardHandler>(
      new PortForwardHandler(_socketHandler, _pipeSocketHandler));
  InitialPayload payload;
  payload.set_jumphost(jumphost);

  for (const auto& envVar : envVars) {
    (*payload.mutable_environmentvariables())[envVar.first] = envVar.second;
  }

  // Tracks which reverse-tunnel requests asked for an OS-assigned port
  // so we can announce the actual allocation when the server's per-tunnel
  // PortForwardSourceResponses arrive in the InitialResponse.
  struct ReverseRequestSummary {
    bool dynamicPort;
    string destinationName;
    int destinationPort;
  };
  vector<ReverseRequestSummary> reverseRequestSummaries;

  try {
    if (tunnels.length()) {
      // Forward (-t/-L) tunnels: gateway-ports applies, mirroring ssh -g.
      auto pfsrs = parseRangesToRequests(tunnels, gatewayPorts);
#ifdef WIN32
      const uid_t myUid = static_cast<uid_t>(-1);
      const gid_t myGid = static_cast<gid_t>(-1);
#else
      const uid_t myUid = ::getuid();
      const gid_t myGid = ::getgid();
#endif
      for (auto& pfsr : pfsrs) {
        auto pfsresponse =
            portForwardHandler->createSource(pfsr, nullptr, myUid, myGid);
        if (pfsresponse.has_error()) {
          if (exitOnForwardFailure) {
            CLOG(INFO, "stderr")
                << "Could not request local forward: " << pfsresponse.error()
                << endl;
            exit(1);
          }
          LOG(WARNING) << "Failed to establish port forward "
                       << pfsr.source().port() << ":"
                       << pfsr.destination().port() << " - "
                       << pfsresponse.error();
          continue;
        }
        // Mirror ssh's behavior of announcing OS-assigned ports for
        // dynamic (port=0) requests.
        if (pfsr.has_source() && pfsr.source().has_port() &&
            pfsr.source().port() == 0 && pfsresponse.has_actual_port()) {
          CLOG(INFO, "stderr")
              << "Allocated port " << pfsresponse.actual_port()
              << " for local forward to " << pfsr.destination().name() << ":"
              << pfsr.destination().port() << endl;
        }
      }
    }
    if (reverseTunnels.length()) {
      // Reverse (-r/-R) tunnels bind on the server. OpenSSH controls this via
      // sshd's GatewayPorts setting, not the client's -g flag, so we never
      // apply gateway-ports here. Users wanting wildcard for -r should use
      // explicit ssh-style "*:port:host:hp" or "0.0.0.0:port:host:hp".
      auto pfsrs = parseRangesToRequests(reverseTunnels);
      for (auto& pfsr : pfsrs) {
        // Remember which reverse-forward requests asked for a dynamic port
        // so we can announce the allocation once the server's
        // PortForwardSourceResponse arrives in the InitialResponse.
        reverseRequestSummaries.push_back(
            {pfsr.has_source() && pfsr.source().has_port() &&
                 pfsr.source().port() == 0,
             pfsr.has_destination() ? pfsr.destination().name() : string(),
             pfsr.has_destination() && pfsr.destination().has_port()
                 ? pfsr.destination().port()
                 : 0});
        *(payload.add_reversetunnels()) = pfsr;
      }
    }
    if (forwardSshAgent) {
      PortForwardSourceRequest pfsr;
      string authSock = "";
      if (identityAgent.length()) {
        authSock.assign(identityAgent);
      } else {
        auto authSockEnv = getenv("SSH_AUTH_SOCK");
        if (!authSockEnv) {
          CLOG(INFO, "stdout")
              << "Missing environment variable SSH_AUTH_SOCK.  Are you sure "
                 "you "
                 "ran ssh-agent first?"
              << endl;
          exit(1);
        }
        authSock.assign(authSockEnv);
      }
      if (authSock.length()) {
        pfsr.mutable_destination()->set_name(authSock);
        pfsr.set_environmentvariable("SSH_AUTH_SOCK");
        *(payload.add_reversetunnels()) = pfsr;
      }
    }
  } catch (const std::runtime_error& ex) {
    CLOG(INFO, "stdout") << "Error establishing port forward: " << ex.what()
                         << endl;
    exit(1);
  }

  connection = shared_ptr<ClientConnection>(
      new ClientConnection(_socketHandler, _socketEndpoint, id, passkey));

  int connectFailCount = 0;
  while (true) {
    try {
      bool fail = true;
      if (connection->connect()) {
        connection->writePacket(
            Packet(EtPacketType::INITIAL_PAYLOAD, protoToString(payload)));
        fd_set rfd;
        timeval tv;
        for (int a = 0; a < 3; a++) {
          FD_ZERO(&rfd);
          int clientFd = connection->getSocketFd();
          if (clientFd < 0) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
          }
          FD_SET(clientFd, &rfd);
          tv.tv_sec = 1;
          tv.tv_usec = 0;
          select(clientFd + 1, &rfd, NULL, NULL, &tv);
          if (FD_ISSET(clientFd, &rfd)) {
            Packet initialResponsePacket;
            if (connection->readPacket(&initialResponsePacket)) {
              if (initialResponsePacket.getHeader() !=
                  EtPacketType::INITIAL_RESPONSE) {
                CLOG(INFO, "stdout") << "Error: Missing initial response\n";
                STFATAL << "Missing initial response!";
              }
              auto initialResponse = stringToProto<InitialResponse>(
                  initialResponsePacket.getPayload());
              if (initialResponse.has_error()) {
                CLOG(INFO, "stdout") << "Error initializing connection: "
                                     << initialResponse.error() << endl;
                exit(1);
              }
              // Announce ports allocated by the server for any reverse
              // forwards that requested port=0, mirroring OpenSSH.
              const int responseCount =
                  initialResponse.reversetunnel_responses_size();
              bool reverseFailureSeen = false;
              for (size_t i = 0; i < reverseRequestSummaries.size() &&
                                 static_cast<int>(i) < responseCount;
                   ++i) {
                const auto& summary = reverseRequestSummaries[i];
                const auto& resp = initialResponse.reversetunnel_responses(i);
                if (resp.has_error()) {
                  reverseFailureSeen = true;
                  CLOG(INFO, "stderr") << "Could not request remote forward to "
                                       << summary.destinationName << ":"
                                       << summary.destinationPort << ": "
                                       << resp.error() << endl;
                  continue;
                }
                if (summary.dynamicPort && resp.has_actual_port()) {
                  CLOG(INFO, "stderr")
                      << "Allocated port " << resp.actual_port()
                      << " for remote forward to " << summary.destinationName
                      << ":" << summary.destinationPort << endl;
                }
              }
              if (reverseFailureSeen && exitOnForwardFailure) {
                exit(1);
              }
              fail = false;
              break;
            }
          }
        }
      }
      if (fail) {
        LOG(WARNING) << "Connecting to server failed: Connect timeout";
        connectFailCount++;
        if (connectFailCount == 3) {
          throw std::runtime_error("Connect Timeout");
        }
      }
    } catch (const runtime_error& err) {
      LOG(INFO) << "Could not make initial connection to server";
      CLOG(INFO, "stdout") << "Could not make initial connection to "
                           << _socketEndpoint << ": " << err.what() << endl;
      exit(1);
    }

    TelemetryService::get()->logToDatadog("Connection Established",
                                          el::Level::Info, __FILE__, __LINE__);
    break;
  }
  VLOG(1) << "Client created with id: " << connection->getId();
};

TerminalClient::~TerminalClient() {
  connection->shutdown();
  console.reset();
  portForwardHandler.reset();
  connection.reset();
}

namespace {

// Strip leading/trailing ASCII whitespace from `s`.
string trim(const string& s) {
  size_t start = 0;
  while (start < s.size() && (s[start] == ' ' || s[start] == '\t' ||
                              s[start] == '\r' || s[start] == '\n')) {
    ++start;
  }
  size_t end = s.size();
  while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' ||
                         s[end - 1] == '\r' || s[end - 1] == '\n')) {
    --end;
  }
  return s.substr(start, end - start);
}

void writeStderrLine(const string& s) {
#ifdef WIN32
  (void)s;
#else
  string line = s + "\r\n";
  ssize_t total = 0;
  while (total < static_cast<ssize_t>(line.size())) {
    ssize_t n =
        ::write(STDERR_FILENO, line.data() + total, line.size() - total);
    if (n <= 0) break;
    total += n;
  }
#endif
}

}  // namespace

void TerminalClient::handleEscapeCommand(const string& rawLine) {
  const string line = trim(rawLine);
  if (line.empty()) {
    return;
  }
  // Recognize OpenSSH-style action prefixes: "-L "/"-R " for additions
  // and "-KL "/"-KR " for cancellations. The rest of the line is either
  // a tunnel specification (parseRangesToRequests) or a port number.
  string action;
  string rest;
  auto consumeActionToken = [&](const string& token) -> bool {
    const size_t n = token.size();
    if (line.size() >= n && line.compare(0, n, token) == 0 &&
        (line.size() == n || line[n] == ' ' || line[n] == '\t')) {
      action = token.substr(1);  // Strip the leading '-' for messages.
      rest = line.size() > n ? trim(line.substr(n)) : string();
      return true;
    }
    return false;
  };
  if (consumeActionToken("-KL") || consumeActionToken("-KR") ||
      consumeActionToken("-L") || consumeActionToken("-R")) {
    // Matched.
  } else {
    writeStderrLine("et: unknown command: " + line);
    writeStderrLine("    supported: -L spec, -R spec, -KL port, -KR port");
    return;
  }
  if (rest.empty()) {
    writeStderrLine("et: -" + action + " requires an argument");
    return;
  }

  // Cancellations take a single port and do not go through the tunnel
  // parser at all.
  if (action == "KL" || action == "KR") {
    int port = 0;
    try {
      size_t consumed = 0;
      port = std::stoi(rest, &consumed);
      if (consumed != rest.size() || port <= 0 || port > 65535) {
        throw std::invalid_argument("port out of range");
      }
    } catch (const std::exception&) {
      writeStderrLine(string("et: -") + action +
                      " expects a port number, got: " + rest);
      return;
    }
    if (action == "KL") {
      const bool removed = portForwardHandler->cancelSourceByPort(port);
      if (removed) {
        std::ostringstream oss;
        oss << "Cancelled local forward on port " << port;
        writeStderrLine(oss.str());
      } else {
        std::ostringstream oss;
        oss << "et: no local forward is bound to port " << port;
        writeStderrLine(oss.str());
      }
    } else {
      // -KR: round-trip to the server.
      et::PortForwardCancelRequest cancelReq;
      cancelReq.set_port(port);
      try {
        connection->writePacket(
            Packet(TerminalPacketType::CANCEL_REVERSE_FORWARD_REQUEST,
                   protoToString(cancelReq)));
      } catch (const std::runtime_error& ex) {
        writeStderrLine(string("et: failed to send cancel request: ") +
                        ex.what());
      }
    }
    return;
  }

  vector<PortForwardSourceRequest> pfsrs;
  try {
    pfsrs = parseRangesToRequests(rest, gatewayPorts);
  } catch (const TunnelParseException& ex) {
    writeStderrLine(string("et: ") + ex.what());
    return;
  }

  if (action == "L") {
#ifdef WIN32
    const uid_t myUid = static_cast<uid_t>(-1);
    const gid_t myGid = static_cast<gid_t>(-1);
#else
    const uid_t myUid = ::getuid();
    const gid_t myGid = ::getgid();
#endif
    for (auto& pfsr : pfsrs) {
      auto pfsresponse =
          portForwardHandler->createSource(pfsr, nullptr, myUid, myGid);
      if (pfsresponse.has_error()) {
        writeStderrLine("et: could not request local forward: " +
                        pfsresponse.error());
        continue;
      }
      if (pfsr.has_source() && pfsr.source().has_port() &&
          pfsr.source().port() == 0 && pfsresponse.has_actual_port()) {
        std::ostringstream oss;
        oss << "Allocated port " << pfsresponse.actual_port()
            << " for local forward to " << pfsr.destination().name() << ":"
            << pfsr.destination().port();
        writeStderrLine(oss.str());
      }
    }
  } else {
    // "-R" must round-trip through the server: the listener binds on the
    // remote side. Send each parsed request and remember the user-facing
    // destination so the ADD_REVERSE_FORWARD_RESPONSE handler can echo
    // an "Allocated port ..." line that mentions the right host.
    for (auto& pfsr : pfsrs) {
      PendingReverseAdd pending{
          pfsr.has_source() && pfsr.source().has_port() &&
              pfsr.source().port() == 0,
          pfsr.has_destination() ? pfsr.destination().name() : string(),
          pfsr.has_destination() && pfsr.destination().has_port()
              ? pfsr.destination().port()
              : 0};
      pendingReverseAdds.push_back(pending);
      try {
        connection->writePacket(
            Packet(TerminalPacketType::ADD_REVERSE_FORWARD_REQUEST,
                   protoToString(pfsr)));
      } catch (const std::runtime_error& ex) {
        pendingReverseAdds.pop_back();
        writeStderrLine(string("et: failed to send remote-forward request: ") +
                        ex.what());
      }
    }
  }
}

void TerminalClient::run(const string& command, const bool noexit) {
  if (console) {
    console->setup();
  }

// TE sends/receives data to/from the shell one char at a time.
#define BUF_SIZE (16 * 1024)
  char b[BUF_SIZE];

  // Filters OpenSSH-style escape sequences (`~.`, `~~`, `~?`, `~C`)
  // out of the stdin byte stream before they are forwarded to the
  // remote shell.
  EscapeProcessor escapeProcessor(
      [this](const string& line) { handleEscapeCommand(line); },
      [this]() { shutdown(); });

  time_t keepaliveTime = time(NULL) + keepaliveDuration;
  bool waitingOnKeepalive = false;

  if (command.length()) {
    LOG(INFO) << "Got command: " << command;
    et::TerminalBuffer tb;
    if (noexit)
      tb.set_buffer(command + "\n");
    else
      tb.set_buffer(command + "; exit\n");

    connection->writePacket(
        Packet(TerminalPacketType::TERMINAL_BUFFER, protoToString(tb)));
  }

  TerminalInfo lastTerminalInfo;

  if (!console.get()) {
    // NOTE: ../../scripts/ssh-et relies on the wording of this message, so if
    // you change it please update it as well.
    CLOG(INFO, "stdout") << "ET running, feel free to background..." << endl;
  }

  while (!connection->isShuttingDown()) {
    {
      lock_guard<recursive_mutex> guard(shutdownMutex);
      if (shuttingDown) {
        break;
      }
    }
    // Data structures needed for select() and
    // non-blocking I/O.
    fd_set rfd;
    timeval tv;

    FD_ZERO(&rfd);
    int maxfd = -1;
    int consoleFd = -1;
    if (console) {
      consoleFd = console->getFd();
      maxfd = consoleFd;
      FD_SET(consoleFd, &rfd);
    }
    int clientFd = connection->getSocketFd();
    if (clientFd > 0) {
      FD_SET(clientFd, &rfd);
      maxfd = max(maxfd, clientFd);
    }
    // Include port forward sockets in select for low-latency forwarding.
    set<int> pfFds;
    portForwardHandler->getForwardFds(&pfFds);
    for (int fd : pfFds) {
      FD_SET(fd, &rfd);
      maxfd = max(maxfd, fd);
    }
    tv.tv_sec = 0;
    tv.tv_usec = 10000;
    select(maxfd + 1, &rfd, NULL, NULL, &tv);

    try {
      if (console) {
        // Check for data to send.
        if (FD_ISSET(consoleFd, &rfd)) {
          // Read from stdin and write to our client that will then send it to
          // the server.
          VLOG(4) << "Got data from stdin";
#ifdef WIN32
          DWORD events;
          INPUT_RECORD buffer[128];
          HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
          PeekConsoleInput(handle, buffer, 128, &events);
          if (events > 0) {
            ReadConsoleInput(handle, buffer, 128, &events);
            string s;
            for (int keyEvent = 0; keyEvent < events; keyEvent++) {
              if (buffer[keyEvent].EventType == KEY_EVENT &&
                  buffer[keyEvent].Event.KeyEvent.bKeyDown) {
                char charPressed =
                    ((char)buffer[keyEvent].Event.KeyEvent.uChar.AsciiChar);
                if (charPressed) {
                  s += charPressed;
                }
              }
            }
            if (s.length()) {
              et::TerminalBuffer tb;
              tb.set_buffer(s);

              connection->writePacket(Packet(
                  TerminalPacketType::TERMINAL_BUFFER, protoToString(tb)));
              keepaliveTime = time(NULL) + keepaliveDuration;
            }
          }
#else
          if (console) {
            int rc = ::read(consoleFd, b, BUF_SIZE);
            int savedErrno = errno;  // Save errno before any logging
            if (rc > 0) {
              // Run the bytes through the escape processor; it returns
              // the bytes that should still be forwarded (anything not
              // consumed as part of `~.`, `~~`, `~?`, or `~C`).
              string s = escapeProcessor.process(b, rc);
              if (!s.empty()) {
                et::TerminalBuffer tb;
                tb.set_buffer(s);

                connection->writePacket(Packet(
                    TerminalPacketType::TERMINAL_BUFFER, protoToString(tb)));
                keepaliveTime = time(NULL) + keepaliveDuration;
              }
            } else if (rc == 0) {
              LOG(INFO) << "Console EOF";
              break;
            } else {
              if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK) {
                // Transient error, retry
              } else {
                LOG(INFO) << "Console read error: (" << savedErrno
                          << "): " << strerror(savedErrno);
                break;
              }
            }
          }
#endif
        }
      }

      if (clientFd > 0 && FD_ISSET(clientFd, &rfd)) {
        VLOG(4) << "Clientfd is selected";
        while (connection->hasData()) {
          VLOG(4) << "connection has data";
          Packet packet;
          if (!connection->read(&packet)) {
            break;
          }
          uint8_t packetType = packet.getHeader();
          if (packetType == et::TerminalPacketType::PORT_FORWARD_DATA ||
              packetType ==
                  et::TerminalPacketType::PORT_FORWARD_DESTINATION_REQUEST ||
              packetType ==
                  et::TerminalPacketType::PORT_FORWARD_DESTINATION_RESPONSE) {
            keepaliveTime = time(NULL) + keepaliveDuration;
            VLOG(4) << "Got PF packet type " << packetType;
            portForwardHandler->handlePacket(packet, connection);
            continue;
          }
          switch (packetType) {
            case et::TerminalPacketType::TERMINAL_BUFFER: {
              if (console) {
                VLOG(3) << "Got terminal buffer";
                // Read from the server and write to our fake terminal
                et::TerminalBuffer tb =
                    stringToProto<et::TerminalBuffer>(packet.getPayload());
                const string& s = tb.buffer();
                // VLOG(5) << "Got message: " << s;
                // VLOG(1) << "Got byte: " << int(b) << " " << char(b) << " " <<
                // connection->getReader()->getSequenceNumber();
                keepaliveTime = time(NULL) + keepaliveDuration;
                console->write(s);
              }
              break;
            }
            case et::TerminalPacketType::KEEP_ALIVE:
              waitingOnKeepalive = false;
              // This will fill up log file quickly but is helpful for debugging
              // latency issues.
              LOG(INFO) << "Got a keepalive";
              break;
            case et::TerminalPacketType::ADD_REVERSE_FORWARD_RESPONSE: {
              auto resp = stringToProto<et::PortForwardSourceResponse>(
                  packet.getPayload());
              PendingReverseAdd pending{};
              const bool havePending = !pendingReverseAdds.empty();
              if (havePending) {
                pending = pendingReverseAdds.front();
                pendingReverseAdds.pop_front();
              }
              if (resp.has_error()) {
                std::ostringstream oss;
                oss << "et: could not request remote forward";
                if (havePending) {
                  oss << " to " << pending.destinationName << ":"
                      << pending.destinationPort;
                }
                oss << ": " << resp.error();
                writeStderrLine(oss.str());
              } else if (havePending && pending.dynamicPort &&
                         resp.has_actual_port()) {
                std::ostringstream oss;
                oss << "Allocated port " << resp.actual_port()
                    << " for remote forward to " << pending.destinationName
                    << ":" << pending.destinationPort;
                writeStderrLine(oss.str());
              }
              break;
            }
            case et::TerminalPacketType::CANCEL_REVERSE_FORWARD_RESPONSE: {
              auto resp = stringToProto<et::PortForwardCancelResponse>(
                  packet.getPayload());
              std::ostringstream oss;
              if (resp.has_error()) {
                oss << "et: could not cancel remote forward";
                if (resp.has_port()) {
                  oss << " on port " << resp.port();
                }
                oss << ": " << resp.error();
              } else {
                oss << "Cancelled remote forward on port "
                    << (resp.has_port() ? resp.port() : 0);
              }
              writeStderrLine(oss.str());
              break;
            }
            default:
              STFATAL << "Unknown packet type: " << int(packetType);
          }
        }
      }

      if (clientFd > 0 && keepaliveTime < time(NULL)) {
        keepaliveTime = time(NULL) + keepaliveDuration;
        if (waitingOnKeepalive) {
          LOG(INFO) << "Missed a keepalive, killing connection.";
          connection->closeSocketAndMaybeReconnect();
          waitingOnKeepalive = false;
        } else {
          LOG(INFO) << "Writing keepalive packet";
          connection->writePacket(Packet(TerminalPacketType::KEEP_ALIVE, ""));
          waitingOnKeepalive = true;
        }
      }
      if (clientFd < 0) {
        // We are disconnected, so stop waiting for keepalive.
        waitingOnKeepalive = false;
      }

      if (console) {
        TerminalInfo ti = console->getTerminalInfo();

        if (ti != lastTerminalInfo) {
          LOG(INFO) << "Window size changed: row: " << ti.row()
                    << " column: " << ti.column() << " width: " << ti.width()
                    << " height: " << ti.height();
          lastTerminalInfo = ti;
          connection->writePacket(
              Packet(TerminalPacketType::TERMINAL_INFO, protoToString(ti)));
        }
      }

      vector<PortForwardDestinationRequest> requests;
      vector<PortForwardData> dataToSend;
      portForwardHandler->update(&requests, &dataToSend);
      for (auto& pfr : requests) {
        connection->writePacket(
            Packet(TerminalPacketType::PORT_FORWARD_DESTINATION_REQUEST,
                   protoToString(pfr)));
        VLOG(4) << "send PF request";
        keepaliveTime = time(NULL) + keepaliveDuration;
      }
      for (auto& pwd : dataToSend) {
        connection->writePacket(
            Packet(TerminalPacketType::PORT_FORWARD_DATA, protoToString(pwd)));
        VLOG(4) << "send PF data";
        keepaliveTime = time(NULL) + keepaliveDuration;
      }
    } catch (const runtime_error& re) {
      STERROR << "Error: " << re.what();
      CLOG(INFO, "stdout") << "Connection closing because of error: "
                           << re.what() << endl;
      lock_guard<recursive_mutex> guard(shutdownMutex);
      shuttingDown = true;
    }
  }
  if (console) {
    console->teardown();
  }
  CLOG(INFO, "stdout") << "Session terminated" << endl;
}
}  // namespace et
