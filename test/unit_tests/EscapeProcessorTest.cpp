#include "EscapeProcessor.hpp"
#include "TestHeaders.hpp"

using namespace et;

namespace {

// Helper that drives an EscapeProcessor by feeding it a string in one shot
// and collecting the bytes that should be forwarded to the server plus any
// commands and terminate signals that fired along the way.
struct Drive {
  string forwarded;
  vector<string> commands;
  int terminateCalls = 0;

  void run(const string& input) {
    EscapeProcessor proc([this](const string& cmd) { commands.push_back(cmd); },
                         [this]() { ++terminateCalls; });
    forwarded = proc.process(input.data(), static_cast<int>(input.size()));
  }
};

}  // namespace

TEST_CASE("Plain typing passes through untouched", "[EscapeProcessor]") {
  Drive d;
  d.run("hello world\n");
  REQUIRE(d.forwarded == "hello world\n");
  REQUIRE(d.commands.empty());
  REQUIRE(d.terminateCalls == 0);
}

TEST_CASE("~~ at start of line emits a single tilde", "[EscapeProcessor]") {
  Drive d;
  d.run("\n~~hi\n");
  // After the first \n we are at line start. ~~ collapses to one ~ that
  // is forwarded; subsequent characters are unchanged.
  REQUIRE(d.forwarded == "\n~hi\n");
  REQUIRE(d.commands.empty());
}

TEST_CASE("~. triggers terminate exactly once", "[EscapeProcessor]") {
  Drive d;
  d.run("\n~.");
  // The escape itself never reaches the wire.
  REQUIRE(d.forwarded == "\n");
  REQUIRE(d.terminateCalls == 1);
}

TEST_CASE("~ in the middle of a line is literal", "[EscapeProcessor]") {
  Drive d;
  d.run("abc~def\n");
  REQUIRE(d.forwarded == "abc~def\n");
  REQUIRE(d.commands.empty());
  REQUIRE(d.terminateCalls == 0);
}

TEST_CASE("~? prints help and is consumed", "[EscapeProcessor]") {
  Drive d;
  d.run("\n~?after\n");
  // "?after" is not part of the help — only `?` is consumed; "after\n"
  // would be the user's next typing. Note that after `~?` we treat the
  // state as line-start (the user sees the next prompt fresh).
  REQUIRE(d.forwarded == "\nafter\n");
  REQUIRE(d.commands.empty());
}

TEST_CASE("Unknown escape verb passes the tilde and verb through",
          "[EscapeProcessor]") {
  Drive d;
  d.run("\n~Xrest\n");
  REQUIRE(d.forwarded == "\n~Xrest\n");
}

TEST_CASE("~C accepts a command line on Enter", "[EscapeProcessor]") {
  Drive d;
  d.run("\n~C-L 8080:host:80\r");
  REQUIRE(d.forwarded == "\n");
  REQUIRE(d.commands.size() == 1);
  REQUIRE(d.commands[0] == "-L 8080:host:80");
}

TEST_CASE("Backspace edits the command-mode line", "[EscapeProcessor]") {
  Drive d;
  // Type "-L 80x", press DEL, then "0:host:80\r".
  string input;
  input.push_back('\n');
  input += "~C-L 80x";
  input.push_back('\x7f');
  input += "0:host:80\r";
  d.run(input);
  REQUIRE(d.commands.size() == 1);
  REQUIRE(d.commands[0] == "-L 800:host:80");
}

TEST_CASE("Ctrl-C aborts a ~C command without dispatching",
          "[EscapeProcessor]") {
  Drive d;
  string input;
  input.push_back('\n');
  input += "~C-L 8080:host:80";
  input.push_back('\x03');  // Ctrl-C cancels.
  d.run(input);
  REQUIRE(d.commands.empty());
}

TEST_CASE("Tilde is only an escape at the start of a line",
          "[EscapeProcessor]") {
  Drive d;
  // First call: "ls\n" puts us at line start. Then `~.` should fire.
  d.run("ls\n~.");
  REQUIRE(d.terminateCalls == 1);

  // Reset and try `~.` mid-line: the tilde must reach the server.
  Drive d2;
  d2.run("ls~.\n");
  REQUIRE(d2.terminateCalls == 0);
  REQUIRE(d2.forwarded == "ls~.\n");
}
