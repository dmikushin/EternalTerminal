#ifndef __ET_ESCAPE_PROCESSOR__
#define __ET_ESCAPE_PROCESSOR__

#include "Headers.hpp"

namespace et {

/**
 * @brief Parses OpenSSH-style escape sequences (`~.`, `~~`, `~?`, `~C`)
 * out of a raw stdin byte stream.
 *
 * The processor is a small state machine that the TerminalClient feeds
 * with bytes read from stdin. It returns the bytes that should still be
 * forwarded to the server (the user's normal typing) and surfaces escape
 * actions through callbacks. Bytes that are part of an escape sequence
 * are consumed and never sent to the remote shell.
 *
 * Behavior matches OpenSSH:
 *   - `~` is only recognized as the escape character at the start of a
 *     line (i.e. immediately after a newline, or at the start of input).
 *   - `~~` emits a single literal `~` and exits the escape.
 *   - `~.` requests session termination.
 *   - `~?` prints a help text on stderr.
 *   - `~C` enters command mode: subsequent bytes are echoed to stderr
 *     and accumulated until the user presses Enter, at which point the
 *     finished line is delivered via the command callback.
 *   - Any other byte after `~` is treated as a non-match: a literal `~`
 *     and that byte are both forwarded to the server.
 */
class EscapeProcessor {
 public:
  using CommandCallback = std::function<void(const string&)>;
  using TerminateCallback = std::function<void()>;

  EscapeProcessor(CommandCallback onCommand, TerminateCallback onTerminate)
      : commandCallback(std::move(onCommand)),
        terminateCallback(std::move(onTerminate)) {}

  /**
   * @brief Feed a chunk of raw stdin bytes; return the bytes that should
   * be forwarded to the server.
   */
  string process(const char* data, int len);

  /** @brief Returns true while the user is composing a `~C` command. */
  bool inCommandMode() const { return state == State::CommandMode; }

 private:
  enum class State {
    AtLineStart,  // Next `~` will be treated as an escape introducer.
    Mid,          // In the middle of a line; `~` is literal.
    EscapeSeen,   // Previous byte was the introducer `~`; awaiting verb.
    CommandMode,  // Currently accumulating a `~C` command line.
  };

  State state = State::AtLineStart;
  string commandBuffer;
  CommandCallback commandCallback;
  TerminateCallback terminateCallback;

  void emitHelp() const;
  void emitCommandPrompt() const;
};

}  // namespace et
#endif  // __ET_ESCAPE_PROCESSOR__
