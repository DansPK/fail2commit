// Synthetic fixture: an ordinary test hook. `git push origin main` without a
// force form must not be flagged.
const status = ['git', 'push', 'origin', 'main'].join(' ');
console.log(status);