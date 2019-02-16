* More reliable logging
* handling page faults: https://github.com/rurban/libsigsegv
* backtraces if libsigsegv doesn't handle this: https://www.gnu.org/software/libc/manual/html_node/Backtraces.html
* Windows try except if libsigsegv doesn't handle this: https://www.codeproject.com/Articles/1044819/Investigate-crashes-c-stack-trace-and-dumps
* Add more examples
* Add in README an example of lib linking
* Improve thread_storage
* Check if ei_mutex module works correctly on Windows
* Remove unnecessary functions in string module.
* Handle system logging.
