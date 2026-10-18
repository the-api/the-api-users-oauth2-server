// Optional idempotent maintenance migration; never modifies the users table.
exports.up = async (knex) => {
  await knex.raw('CREATE INDEX IF NOT EXISTS "oauthGrants_expiresAt_index" ON "oauthGrants" ("expiresAt")');
};
exports.down = async (knex) => {
  await knex.raw('DROP INDEX IF EXISTS "oauthGrants_expiresAt_index"');
};
