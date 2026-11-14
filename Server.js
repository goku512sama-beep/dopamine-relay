// DOPAMINE relay server - zero dependencies, plain Node.js (>=18).
// Host and clients connect OUT to this server, so no port forwarding / VPN is needed.
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const MAX_ROOMS = 300;
const MAX_CLIENTS = 9;
const rooms = new Map();

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('DOPAMINE relay OK. rooms: ' + rooms.size);
});

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  const acc = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + '\r\n\r\n');
  socket.setNoDelay(true);
  const c = { socket, buf: Buffer.alloc(0), room: null, id: 0, host: false, dropped: false, frag: null };
  socket.on('data', d => { c.buf = Buffer.concat([c.buf, d]); parse(c); });
  socket.on('close', () => drop(c));
  socket.on('error', () => { socket.destroy(); });
});

function send(c, op, payload) {
  if (!c || c.dropped || !c.socket.writable) return;
  const len = payload.length;
  let head;
  if (len < 126) head = Buffer.from([0x80 | op, len]);
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | op; head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | op; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  c.socket.write(Buffer.concat([head, payload]));
}
const sendJSON = (c, o) => send(c, 1, Buffer.from(JSON.stringify(o)));

function parse(c) {
  for (;;) {
    const b = c.buf;
    if (b.length < 2) return;
    const fin = (b[0] & 0x80) !== 0, op = b[0] & 0x0f, masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f, off = 2;
    if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
    else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
    if (len > (1 << 20)) { c.socket.destroy(); return; }
    const mlen = masked ? 4 : 0;
    if (b.length < off + mlen + len) return;
    const payload = Buffer.from(b.subarray(off + mlen, off + mlen + len));
    if (masked) { const m = b.subarray(off, off + 4); for (let i = 0; i < payload.length; i++) payload[i] ^= m[i & 3]; }
    c.buf = b.subarray(off + mlen + len);
    frame(c, fin, op, payload);
    if (c.dropped) return;
  }
}

function frame(c, fin, op, payload) {
  if (op === 8) { send(c, 8, payload.subarray(0, 2)); c.socket.end(); return; }
  if (op === 9) { send(c, 10, payload); return; }
  if (op === 10) return;
  if (op === 0) {
    if (!c.frag) return;
    c.frag.parts.push(payload);
    if (fin) { const f = c.frag; c.frag = null; message(c, f.op, Buffer.concat(f.parts)); }
    return;
  }
  if (fin) message(c, op, payload);
  else c.frag = { op, parts: [payload] };
}

function newCode() {
  for (let n = 0; n < 50; n++) {
    let s = '';
    for (let i = 0; i < 5; i++) s += ALPHA[crypto.randomInt(ALPHA.length)];
    if (!rooms.has(s)) return s;
  }
  return null;
}

function message(c, op, p) {
  if (op === 1) {
    let d;
    try { d = JSON.parse(p.toString('utf8')); } catch (e) { return; }
    if (d.t === 'host' && !c.room) {
      if (rooms.size >= MAX_ROOMS) { sendJSON(c, { t: 'err', m: 'full' }); return; }
      const code = newCode();
      if (!code) { sendJSON(c, { t: 'err', m: 'full' }); return; }
      const room = { code, host: c, clients: new Map(), next: 2 };
      rooms.set(code, room);
      c.room = room; c.host = true; c.id = 1;
      sendJSON(c, { t: 'hosted', code });
    } else if (d.t === 'join' && !c.room) {
      const room = rooms.get(String(d.code || '').toUpperCase());
      if (!room) { sendJSON(c, { t: 'err', m: 'nocode' }); return; }
      if (room.clients.size >= MAX_CLIENTS) { sendJSON(c, { t: 'err', m: 'full' }); return; }
      c.room = room; c.id = room.next++;
      room.clients.set(c.id, c);
      sendJSON(c, { t: 'joined', id: c.id });
      sendJSON(room.host, { t: 'join', id: c.id });
    }
    return;
  }
  if (op !== 2 || !c.room) return;
  const room = c.room;
  if (c.host) {
    if (p.length < 5) return;
    const target = p.readInt32LE(0);
    const out = p.subarray(4); // [mode][data]
    if (target > 0) send(room.clients.get(target), 2, out);
    else for (const [id, cl] of room.clients) if (target === 0 || id !== -target) send(cl, 2, out);
  } else {
    if (p.length < 1) return;
    const head = Buffer.alloc(4);
    head.writeInt32LE(c.id, 0);
    send(room.host, 2, Buffer.concat([head, p]));
  }
}

function drop(c) {
  if (c.dropped) return;
  c.dropped = true;
  const room = c.room;
  if (!room) return;
  if (c.host) {
    rooms.delete(room.code);
    for (const cl of room.clients.values()) { send(cl, 8, Buffer.alloc(0)); cl.socket.end(); }
  } else {
    room.clients.delete(c.id);
    sendJSON(room.host, { t: 'leave', id: c.id });
  }
}

setInterval(() => {
  for (const room of rooms.values()) {
    send(room.host, 9, Buffer.alloc(0));
    for (const cl of room.clients.values()) send(cl, 9, Buffer.alloc(0));
  }
}, 20000);

server.listen(PORT, () => console.log('DOPAMINE relay listening on ' + PORT));