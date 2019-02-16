* Add more examples.
* Add Tests.
* Remove `thread_` prefix in mutex and cond modules.
* Remove `thread` module in favor of C11 multithreading API, or set C11 optional to keep `thread` API in `LibUnknownEcho`.
* Find a workaround for console color in Windows.
* Improve queue container with atomics.