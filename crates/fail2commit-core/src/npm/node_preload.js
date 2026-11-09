'use strict';
// fail2commit (CR-014): loaded with `node --require` into npm lifecycle scripts
// that run inside the Windows AppContainer sandbox.
//
// libuv creates the stdio pipes of a child process as `\\?\pipe\uv\...` in the
// global named-pipe namespace. An AppContainer may not create pipes there, and
// libuv reads the ERROR_ACCESS_DENIED as a name collision and retries forever,
// so `execFileSync`, `spawnSync`, `exec` and `spawn` with piped stdio hang.
// This preload routes piped child stdio through files in the job's own TEMP
// directory instead. It runs inside the sandbox and grants nothing: the files
// are in the job's writable stage, which the job can already write.
(function () {
  if (process.platform !== 'win32' || global.__f2cPipesViaFiles) return;
  global.__f2cPipesViaFiles = true;

  const fs = require('fs');
  const path = require('path');
  const cp = require('child_process');
  const { Readable } = require('stream');

  // F2C_IO_DIR is the job's writable temp directory. Windows replaces TEMP for
  // AppContainer processes with a profile folder that may not exist.
  const dir = process.env.F2C_IO_DIR || process.env.TEMP || process.cwd();
  try { fs.mkdirSync(dir, { recursive: true }); } catch (_) {}
  let seq = 0;
  const tempFile = (tag) =>
    path.join(dir, 'f2c-io-' + process.pid + '-' + Date.now() + '-' + seq++ + '-' + tag);
  const isPipe = (s) => s === undefined || s === null || s === 'pipe' || s === 'overlapped';
  const toBuffer = (input) => {
    if (input == null) return Buffer.alloc(0);
    if (Buffer.isBuffer(input)) return input;
    if (ArrayBuffer.isView(input)) return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
    return Buffer.from(String(input));
  };
  const cleanup = (fd, file) => {
    try { if (fd != null) fs.closeSync(fd); } catch (_) {}
    try { fs.unlinkSync(file); } catch (_) {}
  };

  // Synchronous children: spawnSync, execSync and execFileSync all go through
  // the spawn_sync binding, which Node's internals look up at call time.
  let binding = null;
  const quiet = process.noDeprecation;
  process.noDeprecation = true;
  try { binding = process.binding('spawn_sync'); } catch (_) {}
  process.noDeprecation = quiet;
  if (binding && typeof binding.spawn === 'function') {
    const originalSync = binding.spawn;
    binding.spawn = function (options) {
      const files = [];
      try {
        if (options && Array.isArray(options.stdio)) {
          options.stdio = options.stdio.map((s, i) => {
            if (!s || s.type !== 'pipe') return s;
            const file = tempFile('s' + i);
            if (i === 0) {
              fs.writeFileSync(file, toBuffer(s.input));
              const fd = fs.openSync(file, 'r');
              files.push({ i, file, fd, out: false });
              return { type: 'fd', fd };
            }
            const fd = fs.openSync(file, 'w+');
            files.push({ i, file, fd, out: true });
            return { type: 'fd', fd };
          });
        }
        const result = originalSync.call(this, options);
        if (result && Array.isArray(result.output)) {
          for (const f of files) if (f.out) result.output[f.i] = fs.readFileSync(f.file);
        }
        return result;
      } finally {
        for (const f of files) cleanup(f.fd, f.file);
      }
    };
  }

  // Asynchronous children: spawn, exec, execFile and fork all end in
  // ChildProcess.prototype.spawn. Output files are tailed into ordinary
  // Readable streams, and 'close' waits until they have ended.
  const proto = cp.ChildProcess && cp.ChildProcess.prototype;
  if (proto && typeof proto.spawn === 'function') {
    const originalSpawn = proto.spawn;
    proto.spawn = function (options) {
      if (!options || typeof options !== 'object') return originalSpawn.call(this, options);
      let stdio = options.stdio;
      if (typeof stdio === 'string') stdio = [stdio, stdio, stdio];
      else if (!Array.isArray(stdio)) stdio = [undefined, undefined, undefined];
      else stdio = stdio.slice();
      while (stdio.length < 3) stdio.push(undefined);
      const tails = [];
      for (let i = 0; i < stdio.length; i++) {
        if (!isPipe(stdio[i])) continue;
        if (i === 0 || i > 2) {
          stdio[i] = 'ignore'; // writing to a child's stdin is not supported here
          continue;
        }
        const file = tempFile('a' + i);
        const fd = fs.openSync(file, 'w+');
        stdio[i] = fd;
        tails.push({ i, file, fd });
      }
      if (tails.length === 0) return originalSpawn.call(this, options);
      options.stdio = stdio;
      let ret;
      try {
        ret = originalSpawn.call(this, options);
      } finally {
        for (const t of tails) {
          try { fs.closeSync(t.fd); } catch (_) {}
        }
      }
      const child = this;
      let open = tails.length;
      let deferredClose = null;
      const emit = child.emit;
      child.emit = function (event, ...args) {
        if (event === 'close' && open > 0) {
          deferredClose = [event, ...args];
          return true;
        }
        return emit.call(this, event, ...args);
      };
      const ended = () => {
        open -= 1;
        if (open === 0 && deferredClose) {
          const args = deferredClose;
          deferredClose = null;
          emit.apply(child, args);
        }
      };
      for (const t of tails) {
        const stream = tailFile(t.file, child, ended);
        if (t.i === 1) child.stdout = stream;
        else child.stderr = stream;
        if (Array.isArray(child.stdio)) child.stdio[t.i] = stream;
      }
      return ret;
    };
  }

  function tailFile(file, child, onEnd) {
    let fd = null;
    let pos = 0;
    let done = false;
    const stream = new Readable({ read() {} });
    const buf = Buffer.alloc(64 * 1024);
    const drain = () => {
      try {
        if (fd === null) fd = fs.openSync(file, 'r');
        for (;;) {
          const n = fs.readSync(fd, buf, 0, buf.length, pos);
          if (n <= 0) break;
          pos += n;
          stream.push(Buffer.from(buf.subarray(0, n)));
        }
      } catch (_) {}
    };
    const timer = setInterval(drain, 25);
    const finish = () => {
      if (done) return;
      done = true;
      clearInterval(timer);
      // Grandchildren may still hold the file; give them a moment.
      setTimeout(() => {
        drain();
        cleanup(fd, file);
        stream.push(null);
        // Unread output must not hold 'close' back forever.
        setImmediate(() => { if (!stream.readableEnded && !stream.readableFlowing) stream.resume(); });
      }, 30);
    };
    stream.once('end', onEnd);
    child.once('exit', finish);
    child.once('error', () => { if (!child.pid) finish(); });
    return stream;
  }
})();
