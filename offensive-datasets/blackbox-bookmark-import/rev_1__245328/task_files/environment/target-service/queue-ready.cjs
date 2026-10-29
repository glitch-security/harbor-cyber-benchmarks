// Readiness probe: exit 0 once the liteque queue schema (the `tasks` table in
// /data/queue.db) has been created by the workers' ensureInit(). Used by
// start-app.sh to start the web server only AFTER the queue is ready, avoiding a
// web->queue enqueue race ("no such table: tasks") on fresh/reset state.
// Placed under apps/workers so require("better-sqlite3") resolves from here.
try {
  const Database = require("better-sqlite3");
  const db = new Database(process.env.QUEUE_DB || "/data/queue.db", { readonly: true });
  const row = db
    .prepare("select count(*) c from sqlite_master where type='table' and name='tasks'")
    .get();
  process.exit(row && row.c ? 0 : 1);
} catch (e) {
  process.exit(1);
}
