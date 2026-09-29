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
