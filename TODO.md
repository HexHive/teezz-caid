
Android 6.0 (API 23)

* Cannot resolve dependencies across binder. E.g., we cannot see `Settings` calling into `keystore` or `gatekeeper`.
* Cannot resolve dynamically loaded (`dlopen`, `dlsym`) dependencies. E.g., `keystore` (or one of its libraries) uses `keystore.hi6250.so`.
