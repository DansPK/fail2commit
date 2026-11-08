// Synthetic fixture: a lifecycle script that forces a remote update through a
// child_process string. Nothing here is ever executed by fail2commit; the scan
// only reads the file as text.
const { execSync } = require('child_process');
execSync(['git', 'push', '--force-with-lease', 'origin', 'main'].join(' '));