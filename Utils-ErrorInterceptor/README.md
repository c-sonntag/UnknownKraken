## Description

A lightweight and cross-plateform library to handle stacktrace and logging in C99.

## Examples

All examples are in `examples` directory.

### Stacktrace

```bash
./bin/<debug|release>/examples/stacktrace_example
```

```c
#include <ei/ei.h>

#include <stdlib.h>

bool foo(void *parameter) {
    if (!parameter) {
        ei_stacktrace_push_msg("Specified parameter is invalid");
        return false;
    }

    return true;
}

bool bar(void *parameter) {
    if (!foo(parameter)) {
        ei_stacktrace_push_msg("foo failed :(");
        return false;
    }

    return true;
}

/**
 * output:
 * bar failed ! (thread 140371337471744)
 * Caused by: Specified parameter is invalid
 *    at foo (stacktrace_example.c:7)
 *    at bar (stacktrace_example.c:16)
 *    at main (stacktrace_example.c:31)
 */
int main() {
    void *arg;

    arg = NULL;

    ei_init();

    if (!bar(arg)) {
        ei_stacktrace_push_msg("bar failed !");
    }

    ei_stacktrace_print();

    ei_uninit();

    return EXIT_SUCCESS;
}
```

### Logger

```bash
./bin/<debug|release>/examples/logger_example
```

```c
#include <ei/ei.h>

#include <stdlib.h>

int main() {
    ei_init();

    ei_logger_trace("Loading library...");

    ei_logger_debug("Variable value is %d", 58);

    ei_logger_info("User %s is now connected", "username");

    ei_logger_warn("Loading time is consequently longer");

    ei_logger_error("Invalid password");

    ei_logger_fatal("Out of memory");

    ei_uninit();

    return EXIT_SUCCESS;
}
```

Output:

![logger example](/img/logger_example.png)

## Build

### Debug mode
```bash
./build_debug.sh
```

### Release mode
```bash
./build_release.sh
```

### Clean
```bash
./clean.sh
```

### Install
```bash
./build_release.sh && sudo ./install.sh
```

## Cross-plateform

Tested on:
* Windows x86
* Windows 64
* Ubuntu 14.04
* Ubuntu 16.04
