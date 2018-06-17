## Description

LibMemoryPlugin is a library that provides a simple API to create, load and update plugin from and to memory of a Windows executable.

## API

Example of use of API without error handling for sake of simplicity.

### Create new plugin

```c
mp_memory_plugin *plugin;
int plugin_id;

/* Create new plugin from buffer */
plugin = mp_memory_plugin_create_new(data, size);

/**
 * Save the plugin into the target path (exec or shared library). It returned the
 * corresponding id of the created plugin.
 */
plugin_id = mp_memory_plugin_save(plugin, target_path);

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
plugin_id = mp_memory_plugin_save(plugin, target_path);

/* Destroy only the object content and not the saved plugin */
mp_memory_plugin_destroy(plugin);
```

### Load a plugin

```c
mp_memory_plugin *plugin;

/* Load plugin from id */
plugin = mp_memory_plugin_load(plugin_id);

/* Get a function from the plugin */
hello_world = mp_memory_plugin_get_function(plugin, "hello_world");

hello_world();

/* Unload the plugin */
mp_memory_plugin_unload(plugin);
```

### Update a plugin

```c
mp_memory_plugin *plugin;

/* Load plugin from id */
plugin = mp_memory_plugin_load(plugin_id);

/* Update the content of the plugin with data/size */
mp_memory_plugin_update_from_buffer(plugin, data, size);

/* Unload the plugin */
mp_memory_plugin_unload(plugin);
```

## Dependencies

* [LibErrorInterceptor](https://github.com/swasun/LibErrorInterceptor), a lightweight and cross-plateform library to handle stacktrace and logging in C99.
* [LibMemorySlot](https://github.com/swasun/LibMemorySlot), a lightweight library to create, update and load slot (the Windows implementation is the Resource API).
* [LibSharedMemoryObject](https://github.com/swasun/LibSharedMemoryObject), a light and cross-plateform library that provides a simple API to load from memory shared library on both Linux (.so) and Windows (.dll).

## Cross-plateform

Tested on:
* Windows x86
* Windows 64
