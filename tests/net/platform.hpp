// The few OS calls the tests make outside Corosio: the process id, a raw
// write to a socket, a readiness poll, the environment, running a command
// and a blocking loopback TCP socket. POSIX on Linux, the CRT and Winsock on
// Windows.
#pragma once

#include <boost/corosio/detail/native_handle.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#ifdef _WIN32
#include <winsock2.h>

#include <process.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
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

// ---------------------------------------------------------------- blocking sockets
//
// For servers that run plain blocking OpenSSL on a thread of their own
// (SSL_set_fd), outside any io_context: BSD sockets on Linux, Winsock on
// Windows.

#ifdef _WIN32
using raw_socket_handle = SOCKET;
inline constexpr raw_socket_handle invalid_raw_socket = INVALID_SOCKET;
#else
using raw_socket_handle = int;
inline constexpr raw_socket_handle invalid_raw_socket = -1;
#endif

// The handle as OpenSSL's SSL_set_fd takes it, and back from SSL_get_fd
// (OpenSSL keeps a Winsock SOCKET in an int; handles fit in 32 bits).
[[nodiscard]] inline auto openssl_fd(raw_socket_handle s) -> int
{
#ifdef _WIN32
	return static_cast<int>(s);
#else
	return s;
#endif
}

[[nodiscard]] inline auto socket_of_openssl_fd(int fd) -> raw_socket_handle
{
#ifdef _WIN32
	return static_cast<raw_socket_handle>(fd);
#else
	return fd;
#endif
}

// Shuts both directions of `s` down: a thread blocked reading it wakes up.
inline void shutdown_both(raw_socket_handle s)
{
#ifdef _WIN32
	(void)::shutdown(s, SD_BOTH);
#else
	(void)::shutdown(s, SHUT_RDWR);
#endif
}

// Bounds each blocking read on `s` to `seconds`.
inline void set_receive_timeout(raw_socket_handle s, int seconds)
{
#ifdef _WIN32
	const DWORD ms = static_cast<DWORD>(seconds) * 1000;
	(void)::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&ms), sizeof ms);
#else
	const timeval limit{ .tv_sec = seconds, .tv_usec = 0 };
	(void)::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof limit);
#endif
}

// One blocking read into `buf`: the byte count, 0 at end of stream, < 0 on
// an error or a timeout.
[[nodiscard]] inline auto receive_some(raw_socket_handle s, std::span<char> buf) -> std::ptrdiff_t
{
#ifdef _WIN32
	return ::recv(s, buf.data(), static_cast<int>(buf.size()), 0);
#else
	return ::recv(s, buf.data(), buf.size(), 0);
#endif
}

// An owned blocking TCP socket, not inheritable by child processes.
class blocking_socket
{
  public:
	blocking_socket() = default;
	explicit blocking_socket(raw_socket_handle s) : handle_(s) {}
	blocking_socket(blocking_socket &&other) noexcept
	  : handle_(std::exchange(other.handle_, invalid_raw_socket)), closed_(std::exchange(other.closed_, false))
	{}
	auto operator=(blocking_socket &&other) noexcept -> blocking_socket &
	{
		if (this != &other) {
			close();
			handle_ = std::exchange(other.handle_, invalid_raw_socket);
			closed_ = std::exchange(other.closed_, false);
		}
		return *this;
	}
	blocking_socket(const blocking_socket &) = delete;
	auto operator=(const blocking_socket &) -> blocking_socket & = delete;
	~blocking_socket() { close(); }

	// A listener on 127.0.0.1 with a port the system picks; not valid()
	// when that failed.
	[[nodiscard]] static auto listen_loopback(int backlog) -> blocking_socket
	{
#ifdef _WIN32
		static const bool started = [] {
			WSADATA data{};
			return ::WSAStartup(MAKEWORD(2, 2), &data) == 0;// never cleaned up: the process ends
		}();
		if (!started) {
			return {};
		}
		blocking_socket s(::WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
#else
		blocking_socket s(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
#endif
		if (!s.valid()) {
			return {};
		}
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (::bind(s.handle_, reinterpret_cast<const sockaddr *>(&addr), sizeof addr) != 0
			|| ::listen(s.handle_, backlog) != 0) {
			return {};
		}
		return s;
	}

	[[nodiscard]] auto valid() const -> bool { return handle_ != invalid_raw_socket && !closed_; }
	[[nodiscard]] auto handle() const -> raw_socket_handle { return handle_; }

	// The local port, 0 when it cannot be read.
	[[nodiscard]] auto port() const -> std::uint16_t
	{
		sockaddr_in addr{};
#ifdef _WIN32
		int len = sizeof addr;
#else
		socklen_t len = sizeof addr;
#endif
		if (::getsockname(handle_, reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
			return 0;
		}
		return ntohs(addr.sin_port);
	}

	// Waits for a connection on a listener; not valid() when that failed
	// (or interrupt() ran).
	[[nodiscard]] auto accept() const -> blocking_socket
	{
#ifdef _WIN32
		blocking_socket s(::accept(handle_, nullptr, nullptr));
		if (s.valid()) {
			(void)::SetHandleInformation(reinterpret_cast<HANDLE>(s.handle_), HANDLE_FLAG_INHERIT, 0);
		}
		return s;
#else
		return blocking_socket(::accept4(handle_, nullptr, nullptr, SOCK_CLOEXEC));
#endif
	}

	// Wakes a thread blocked in accept() on this listener (or reading this
	// socket); the socket is unusable after. Winsock does not wake a blocked
	// accept on shutdown, only on closesocket, so the socket is closed there
	// (the handle stays as it is for the blocked thread).
	void interrupt()// NOLINT(readability-make-member-function-const): the Winsock branch sets closed_
	{
		if (!valid()) {
			return;
		}
#ifdef _WIN32
		(void)::closesocket(handle_);
		closed_ = true;
#else
		shutdown_both(handle_);
#endif
	}

  private:
	void close()
	{
		if (handle_ != invalid_raw_socket && !closed_) {
#ifdef _WIN32
			(void)::closesocket(handle_);
#else
			(void)::close(handle_);
#endif
		}
		handle_ = invalid_raw_socket;
		closed_ = false;
	}

	raw_socket_handle handle_ = invalid_raw_socket;
	bool closed_ = false;// interrupt() closed it already (Winsock)
};

}// namespace jhetz::ldap::test
