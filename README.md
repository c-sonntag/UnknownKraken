## Description

LibMemoryPlugin is a library that provides a simple API to create, load and update plugin from and to memory of a Windows executable.

## API

Example of use of API without error handling for sake of simplicity.

### Create new plugin

```c
mp_memory_plugin *plugin;
int plugin_id;
mp_entry *entry;

entry = mp_entry_create();
mp_entry_add_bytes(entry, data, size);

/* Create new plugin from buffer */
plugin = mp_memory_plugin_create_new(entry);

/**
 * Save the plugin into the target path (exec or shared library). It returned the
 * corresponding id of the created plugin.
 */
plugin_id = mp_memory_plugin_save(plugin, target_path);

mp_entry_destroy(entry);
/* Destroy only the object content and not the saved plugin */
mp_memory_plugin_destroy(plugin);
```

###  Create new empty plugin

```c
mp_memory_plugin *plugin;
int plugin_id;

plugin = mp_memory_plugin_create_empty();

/**
 * Save the plugin into the target path (exec or shared object). It returned the
 * corresponding id of the created plugin. Since the plugin specified in parammeter
 * is empty, the default content and size will be fixed, in order to easily know it's
 * an available slot to update with a new plugin.
 */
plugin_id = mp_memory_plugin_save(plugin, target_path, <optional_crypto_metadata>);

/* Destroy only the object content and not the saved plugin */
mp_memory_plugin_destroy(plugin);
```

### Load a plugin

```c
mp_memory_plugin *plugin;

/* Load plugin from id */
plugin = mp_memory_plugin_load(plugin_id, <optional_crypto_metadata>);

/* Get a function from the plugin */
hello_world = mp_memory_plugin_get_function(plugin, "hello_world");

hello_world();

/* Unload the plugin */
mp_memory_plugin_unload(plugin);
```

### Update a plugin

Note that update doesn't work for slot implementation in Windows, since Windows Resource API seems to doens't allow update a resource in the current process in user mode.

```c
mp_memory_plugin *plugin;
mp_entry *entry;

/* Load plugin from id */
plugin = mp_memory_plugin_load(plugin_id, <optional_crypto_metadata>);

entry = mp_entry_create();
mp_entry_add_bytes(entry, data, size);

/* Update the content of the plugin with data/size */
mp_memory_plugin_update(plugin, entry, <optional_crypto_metadata>);

mp_entry_destroy(entry);
/* Unload the plugin */
mp_memory_plugin_unload(plugin);
```

## Dependencies

### Mandatory

Core dependencies, without encryption.

* [LibErrorInterceptor](https://github.com/swasun/LibErrorInterceptor), a lightweight and cross-plateform library to handle stacktrace and logging in C99.
* [LibMemorySlot](https://github.com/swasun/LibMemorySlot), a lightweight library to create, update and load slot (the Windows implementation is the Resource API).
* [LibSharedMemoryObject](https://github.com/swasun/LibSharedMemoryObject), a light and cross-plateform library that provides a simple API to load from memory shared library on both Linux (.so) and Windows (.dll).
* [LibUnknownEchoUtilsModule](https://github.com/swasun/LibUnknownEchoUtilsModule) Utils module of [LibUnknownEcho](https://github.com/swasun/LibUnknownEcho). Last version

### Optional

Additional depdendencies to add an encryption layer.

* [LibUnknownEchoCryptoModule](https://github.com/swasun/LibUnknownEchoCryptoModule) Crypto module of [LibUnknownEcho](https://github.com/swasun/LibUnknownEcho). Last version.
* [Libssl](https://github.com/openssl/openssl) Provides the client and server-side implementations for SSLv3 and TLS. Version 1.1
* [Libcrypto](https://github.com/openssl/openssl) Provides general cryptographic and X.509 support needed by SSL/TLS but
	not logically part of it. Version 1.1.
* [Zlib](https://github.com/madler/zlib) A massively spiffy yet delicately unobtrusive compression library. Version 1.2.11.

## Build with encryption layer

### MVS

Just add `"buildCommandArgs": "-DWITH_CRYPTO"` in `"environments"` of `CMakeSettings.json`.

### From command line

Add `-DWITH_CRYPTO` flag in `cmake` command line.

## Cross-plateform

Tested on:
* Windows 10 x86 (tested without encryption, but it should work with)
* Windows 10 64
