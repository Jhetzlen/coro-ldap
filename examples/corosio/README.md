# Boost.Corosio echo examples

A minimal TCP echo server and client written with
[Boost.Corosio](https://github.com/cppalliance/corosio), a coroutine-only
networking library built on [Capy](https://github.com/cppalliance/capy).

This is a standalone CMake project: it does not use the Asio-based code in
the rest of the repository. Corosio and Capy are fetched at pinned commits.

## Build

Requires a C++20 compiler (GCC 12+, Clang 17+, MSVC 14.34+).

```sh
cmake -S examples/corosio -B build/corosio -G Ninja
cmake --build build/corosio
```

The examples build with the same warnings as `ldap/` (`-Wall -Wextra
-Wpedantic -Wconversion -Wsign-conversion -Wshadow`); add
`-DCOROSIO_EXAMPLES_WERROR=ON` to make them errors, as CI does.

## Run

```sh
./build/corosio/corosio_echo_server 8080          # terminal 1
./build/corosio/corosio_echo_client 127.0.0.1 8080 # terminal 2
```

## Corosio compared with Asio

| Asio (`use_awaitable`)                                   | Corosio                                               |
|----------------------------------------------------------|-------------------------------------------------------|
| `net::awaitable<T>`                                      | `capy::task<T>`                                       |
| `co_spawn(ex, f(), detached)`                            | `capy::run_async(ex)(f())`                            |
| Completion token on every call (`use_awaitable`, `as_tuple`, ...) | No tokens: every operation is directly awaitable |
| Errors thrown by default                                 | Structured result: `auto [ec, n] = co_await ...`      |
| `async_read_some` / `async_write`                        | `sock.read_some(buf)` / `capy::write(sock, buf)`      |
| Executor chosen per operation                            | Executor affinity propagates automatically to awaited tasks |

## Calling coroutines from synchronous code

`result_future.hpp` connects coroutines to blocking code without using
exceptions. Results come back as `std::expected<T, std::error_code>`
(`jhetz::result<T>`). It requires C++23.

```cpp
corosio::io_context ioc;

// Run to completion on this thread.
jhetz::result<int> r = jhetz::sync_wait(ioc, compute(21));
if (!r)
    std::cerr << r.error().message() << '\n';

// Or start a task on a context running elsewhere and wait for it later.
jhetz::result_future<int> f = jhetz::spawn_future(ioc.get_executor(), compute(1));
jhetz::result<int> v = f.get();   // blocks, never throws
```

A task can return `T` or `jhetz::result<T>`; both produce a
`result_future<T>`. Errors that would otherwise be exceptions become error codes:

| What happened                          | `error()`                               |
|----------------------------------------|-----------------------------------------|
| Task returned `std::unexpected(ec)`    | `ec`                                    |
| `std::system_error` escaped the task   | its `code()`                            |
| `std::bad_alloc`                       | `std::errc::not_enough_memory`          |
| Any other exception                    | `jhetz::bridge_errc::unhandled_exception` |
| Task destroyed before finishing        | `std::future_errc::broken_promise`      |
| `get()` called twice                   | `std::future_errc::no_state`            |

Never block on a future from the thread running the task's
`io_context`, because that thread is the one that has to finish the task.

```sh
./build/corosio/corosio_result_future
```
