#include "EscapeProcessor.hpp"

namespace et {

namespace {

void writeStderr(const string& s) {
#ifdef WIN32
  // On Windows the console is handled separately; just ignore for now.
  (void)s;
#else
  ssize_t total = 0;
  while (total < static_cast<ssize_t>(s.size())) {
    ssize_t n = ::write(STDERR_FILENO, s.data() + total, s.size() - total);
    if (n <= 0) break;
    total += n;
  }
#endif
}

}  // namespace

void EscapeProcessor::emitHelp() const {
  writeStderr(
      "\r\nSupported escape sequences:\r\n"
      "  ~.   - terminate session\r\n"
      "  ~C   - open a command line (then -L/-R bind:port:host:hp)\r\n"
      "  ~?   - this message\r\n"
      "  ~~   - send the escape character by typing it twice\r\n"
      "(Note that escapes are only recognized immediately after newline.)\r\n");
}

void EscapeProcessor::emitCommandPrompt() const { writeStderr("\r\net> "); }

string EscapeProcessor::process(const char* data, int len) {
  string forward;
  forward.reserve(len);
  for (int i = 0; i < len; ++i) {
    const char c = data[i];
    switch (state) {
      case State::CommandMode: {
        if (c == '\r' || c == '\n') {
          writeStderr("\r\n");
          // Hand off the finished command line for parsing.
          string line;
          line.swap(commandBuffer);
          if (commandCallback) {
            commandCallback(line);
          }
          state = State::AtLineStart;
        } else if (c == 0x03 /* Ctrl-C */ || c == 0x04 /* Ctrl-D */) {
          // Cancel the command without executing.
          writeStderr("\r\n");
          commandBuffer.clear();
          state = State::AtLineStart;
        } else if (c == 0x7f /* DEL/Backspace */ || c == 0x08) {
          if (!commandBuffer.empty()) {
            commandBuffer.pop_back();
            writeStderr("\b \b");
          }
        } else {
          commandBuffer.push_back(c);
          // Echo the character so the user sees what they're typing.
          writeStderr(string(1, c));
        }
        break;
      }
      case State::EscapeSeen: {
        if (c == '~') {
          forward.push_back('~');
          state = State::Mid;
        } else if (c == '.') {
          if (terminateCallback) {
            terminateCallback();
          }
          state = State::AtLineStart;
        } else if (c == 'C') {
          emitCommandPrompt();
          commandBuffer.clear();
          state = State::CommandMode;
        } else if (c == '?') {
          emitHelp();
          state = State::AtLineStart;
        } else {
          // Not an escape we know — pass `~` and the follow-up through.
          forward.push_back('~');
          forward.push_back(c);
          state = (c == '\r' || c == '\n') ? State::AtLineStart : State::Mid;
        }
        break;
      }
      case State::AtLineStart: {
        if (c == '~') {
          state = State::EscapeSeen;
        } else {
          forward.push_back(c);
          if (c != '\r' && c != '\n') {
            state = State::Mid;
          }
        }
        break;
      }
      case State::Mid: {
        forward.push_back(c);
        if (c == '\r' || c == '\n') {
          state = State::AtLineStart;
        }
        break;
      }
    }
  }
  return forward;
}

}  // namespace et
