# autobee-encryption

Encryption module for [Autobee](https://github.com/holepunchto/autobee). Provides encryption classes for writer cores, view cores, and the system core.

## Install

```
npm install autobee-encryption
```

## Usage

```js
const { AutobeeEncryption, WriterEncryption, ViewEncryption } = require('autobee-encryption')
```

### `WriterEncryption`

Encrypts writer (input) cores. Pass an instance as the `encryption` option when creating an Autobase:

```js
const enc = new WriterEncryption(auto)
```

### `ViewEncryption`

Encrypts a named view core:

```js
const enc = new ViewEncryption(auto, 'my-view')
```

### `AutobeeEncryption.setSystemEncryption(bootstrap, encryptionKey, core, opts)`

Helper to configure encryption on the system core. Handles both legacy (manifest v1) and current formats automatically:

```js
await AutobeeEncryption.setSystemEncryption(bootstrap, encryptionKey, systemCore)
```

### `AutobeeEncryption.encryptAnchor(block, bootstrap, encryptionKey, namespace)`

Encrypts an anchor block in-place using the genesis entropy and a derived block key.

## License

Apache-2.0
