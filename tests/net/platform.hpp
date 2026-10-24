// The few OS calls the tests make outside Corosio: the process id, a raw
// write to a socket, a readiness poll, the environment and running a
// command. POSIX on Linux, the CRT and Winsock on Windows.
#pragma once

#include <boost/corosio/detail/native_handle.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <winsock2.h>

#include <process.h>
#else
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace jhetz::ldap::test {

// This process's id, for names unique to a test run.
[[nodiscard]] inline auto process_id() -> int
{
#ifdef _WIN32
	return ::_getpid();
#else
	return static_cast<int>(::getpid());
#endif
}

// Writes `bytes` to the socket in one call, outside the io_context. True when
// all of them went (the tests write a few bytes to an empty socket buffer).
[[nodiscard]] inline auto raw_send(boost::corosio::native_handle_type socket, std::string_view bytes) -> bool
{
#ifdef _WIN32
	const int size = static_cast<int>(bytes.size());
	return ::send(static_cast<SOCKET>(socket), bytes.data(), size, 0) == size;
#else
	return ::write(socket, bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size());
#endif
}

// Whether the socket is readable right now (for a listening socket: a
// connection waits to be accepted). Does not wait.
[[nodiscard]] inline auto poll_readable(boost::corosio::native_handle_type socket) -> bool
{
#ifdef _WIN32
	pollfd p{ .fd = static_cast<SOCKET>(socket), .events = POLLRDNORM, .revents = 0 };
	return ::WSAPoll(&p, 1, 0) == 1;
#else
	::pollfd p{ .fd = socket, .events = POLLIN, .revents = 0 };
	return ::poll(&p, 1, 0) == 1;
#endif
}

// Sets an environment variable. Not thread-safe: call it when no other
// thread runs.
inline void set_env(const char *name, const char *value)
{
#ifdef _WIN32
	(void)::_putenv_s(name, value);
#else
	(void)::setenv(name, value, 1);// NOLINT(concurrency-mt-unsafe): see above
#endif
}

// Removes an environment variable. Not thread-safe, as set_env.
inline void unset_env(const char *name)
{
#ifdef _WIN32
	(void)::_putenv_s(name, "");// an empty value removes it
#else
	(void)::unsetenv(name);// NOLINT(concurrency-mt-unsafe): see above
#endif
}

// `arg` quoted as one word for the shell run_command uses: single quotes
// for sh, double quotes for cmd.exe (and the CRT's argv parsing).
[[nodiscard]] inline auto shell_quote(std::string_view arg) -> std::string
{
	std::string out;
#ifdef _WIN32
	out += '"';
	for (const char c : arg) {
		if (c == '"') {
			out += '\\';
		}
		out += c;
	}
	out += '"';
#else
	out += '\'';
	for (const char c : arg) {
		if (c == '\'') {
			out += "'\\''";
		} else {
			out += c;
		}
	}
	out += '\'';
#endif
	return out;
}

struct command_result
{
	int status{};// the exit code; -1 when the command could not run or did not exit normally
	std::string output{};// stdout and stderr
};

// Runs `command` through the shell (sh, or cmd.exe on Windows) and returns
// its exit code and output. Quote the words with shell_quote.
[[nodiscard]] inline auto run_command(const std::string &command) -> command_result
{
#ifdef _WIN32
	// cmd /c strips the first and last quote of a line that starts with one:
	// the extra pair keeps the command's own quotes. Text mode: CRLF reads
	// as LF.
	FILE *p = ::_popen(("\"" + command + " 2>&1\"").c_str(), "rt");
#else
	// NOLINTNEXTLINE(bugprone-command-processor,cert-env33-c): test-only, runs fixed commands
	FILE *p = ::popen((command + " 2>&1").c_str(), "r");
#endif
	if (p == nullptr) {
		return { .status = -1 };
	}
	command_result r;
	char buf[4096];
	while (const std::size_t n = std::fread(buf, 1, sizeof buf, p)) {
		r.output.append(buf, n);
	}
#ifdef _WIN32
	r.status = ::_pclose(p);// the exit code itself
#else
	const int status = ::pclose(p);
	r.status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
	return r;
}

}// namespace jhetz::ldap::test
