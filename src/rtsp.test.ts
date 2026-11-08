import { deepStrictEqual, rejects, strictEqual } from 'node:assert/strict';
import { createServer, type Server, type Socket } from 'node:net';
import { test } from 'node:test';
import { RtspConnection } from './rtsp.js';

interface Received {
  method: string;
  cseq: string;
  socket: Socket;
}

/** A receiver that hands every request to the test, which decides when to answer. */
async function fakeReceiver(onRequest: (req: Received) => void): Promise<{ server: Server; port: number }> {
  const server = createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        const end = buffer.indexOf('\r\n\r\n');
        if (end < 0) {
          return;
        }
        const head = buffer.subarray(0, end).toString('utf8');
        const length = Number(/content-length:\s*(\d+)/i.exec(head)?.[1] ?? '0');
        if (buffer.length < end + 4 + length) {
          return;
        }
        buffer = buffer.subarray(end + 4 + length);
        const method = head.split(' ')[0] ?? '';
        const cseq = /cseq:\s*(\d+)/i.exec(head)?.[1] ?? '';
        onRequest({ method, cseq, socket });
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  return { server, port: typeof address === 'object' && address ? address.port : 0 };
}

function reply(req: Received, options: { cseq?: string | null; body?: string } = {}): void {
  const body = options.body ?? req.method;
  const cseq = options.cseq === undefined ? req.cseq : options.cseq;
  const cseqLine = cseq === null ? '' : `CSeq: ${cseq}\r\n`;
  req.socket.write(`RTSP/1.0 200 OK\r\n${cseqLine}Content-Length: ${body.length}\r\n\r\n${body}`);
}

test('a response goes to the request with its CSeq, whatever order they come back in', async () => {
  const held: Received[] = [];
  const { server, port } = await fakeReceiver((req) => {
    held.push(req);
    if (held.length === 2) {
      reply(held[1] as Received);
      reply(held[0] as Received);
    }
  });
  const rtsp = new RtspConnection('127.0.0.1', port, '1');
  await rtsp.connect();
  const [first, second] = await Promise.all([rtsp.request('OPTIONS'), rtsp.request('SET_PARAMETER')]);
  strictEqual(first.body.toString(), 'OPTIONS');
  strictEqual(second.body.toString(), 'SET_PARAMETER');
  rtsp.close();
  server.close();
});

test('a late answer to a timed-out request is not handed to the next one', async () => {
  const held: Received[] = [];
  const { server, port } = await fakeReceiver((req) => held.push(req));
  const rtsp = new RtspConnection('127.0.0.1', port, '1');
  await rtsp.connect();
  await rejects(rtsp.request('SET_PARAMETER', { timeoutMs: 50 }), /timed out/);
  const next = rtsp.request('GET_PARAMETER');
  await new Promise((resolve) => setTimeout(resolve, 20));
  reply(held[0] as Received, { body: 'late' });
  reply(held[1] as Received, { body: 'mine' });
  strictEqual((await next).body.toString(), 'mine');
  rtsp.close();
  server.close();
});

test('a receiver that leaves CSeq out is answered in order', async () => {
  const { server, port } = await fakeReceiver((req) => reply(req, { cseq: null }));
  const rtsp = new RtspConnection('127.0.0.1', port, '1');
  await rtsp.connect();
  const answers = await Promise.all([rtsp.request('OPTIONS'), rtsp.request('ANNOUNCE')]);
  deepStrictEqual(
    answers.map((a) => a.body.toString()),
    ['OPTIONS', 'ANNOUNCE'],
  );
  rtsp.close();
  server.close();
});
