---
tags:
  - Exploitation
  - Foundational
  - HTTP
  - Initial_Access
  - Web_Application
---

### Socket.IO Specific [optional]
> [!info] **Socket.IO** uses specific message format and polling fallback.

```bash
# Socket.IO uses HTTP polling before upgrading
curl "https://<TargetHost>/socket.io/?EIO=4&transport=polling"
```

```javascript
const io = require('socket.io-client');
const socket = io('https://<TargetHost>');

socket.on('connect', () => {
  console.log('Connected');
  socket.emit('message', { data: 'test' });
});
```
