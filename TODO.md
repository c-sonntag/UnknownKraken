# Near future

## Security
* Remove in real time outdated or useless certificates in client/server keystores.
* Seed random generator with processor timestamp if needed.
* Set to channel key a lifetime (not too long).
* Use the hash of keystore and key passwords and not the plain data.
* Cipher plain data password.
* Record each CSR response and doesn't delete them if the process is interrupted.
* Checking errno after each system function call.

## Stability
* Add allocation error handling.
* Fix -Wcast-qual, -Wsign-conversion warnings.
* Resolve Clang Code Model warning options and add them to CMakeLists (https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html) (-Weverything).

## Network
* Not disconnect the connection each time it's interrupt (timeout).
* Anticipate the behavior if a specified port is already bound.
* Fix TCP exchanges errors when connection is slow.

## Usability
* Documents, comments.
* Set date logging more readable.
* Clean-up examples.
* Clean-up CMakeLists.txt and scripts.

## Portability
* Make all sources compatible with Windows.

***


# No too distant future

## Security
* Fix possible nickname issue when multiple clients request same nickname.
* Reduce certificates access right.

## Network
* Improve network error handling during message exchanges.
* Make circuit protocol.

## Usability
* Functional examples with Docker.
* Make channel protocol more flexible (w/wo CSR for example).

## Performance
* Improve compilation flags (optimization).

***


# Distant future

## Security
* Make it work with a longer CA chain.
* Protect password/key memory to limits basic reverse engineering.

## Network
* Add IPv6 support.
* Mix UPD and TPC channels.
* Abstract communication (TCP, ...).

## Usability
* Tests with CMocka.
* Network tests.

## Performance
* Check if libasm can be uselful.
* Check for a better malloc implementation.
