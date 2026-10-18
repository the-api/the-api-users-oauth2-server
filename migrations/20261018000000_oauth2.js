exports.up = async (knex) => {
  await knex.schema.createTable('oauthClients', (t) => {
    t.string('id', 128).primary();
    t.string('name', 255).notNullable();
    t.string('secretHash', 64);
    t.string('type', 32).notNullable();
    t.jsonb('redirectUris').notNullable();
    t.jsonb('scopes').notNullable();
    t.boolean('disabled').notNullable().defaultTo(false);
    t.integer('createdBy').references('id').inTable('users').onDelete('SET NULL');
    t.timestamp('timeCreated', { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  await knex.schema.createTable('oauthGrants', (t) => {
    t.string('id', 128).primary();
    t.string('clientId', 128).notNullable().references('id').inTable('oauthClients').onDelete('CASCADE');
    t.integer('userId').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.text('scope').notNullable();
    t.boolean('revoked').notNullable().defaultTo(false);
    t.timestamp('authTime', { useTz: true }).notNullable();
    t.timestamp('expiresAt', { useTz: true }).notNullable();
    t.timestamp('timeCreated', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.index(['userId', 'clientId']);
  });
  // Random credentials are stored only as SHA-256 digests.
  await knex.schema.createTable('oauthCredentials', (t) => {
    t.string('hash', 64).primary();
    t.string('kind', 16).notNullable();
    t.string('grantId', 128).notNullable().references('id').inTable('oauthGrants').onDelete('CASCADE');
    t.jsonb('data').notNullable().defaultTo('{}');
    t.timestamp('expiresAt', { useTz: true }).notNullable();
    t.timestamp('consumedAt', { useTz: true });
    t.index(['grantId']);
    t.index(['expiresAt']);
  });
  await knex.schema.createTable('oauthSessions', (t) => {
    t.string('hash', 64).primary();
    t.integer('userId').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.timestamp('authTime', { useTz: true }).notNullable();
    t.timestamp('expiresAt', { useTz: true }).notNullable().index();
  });
  await knex.schema.createTable('oauthInteractions', (t) => {
    t.string('id', 128).primary();
    t.string('browserHash', 64).notNullable();
    t.string('csrfHash', 64).notNullable();
    t.jsonb('request').notNullable();
    t.integer('userId').references('id').inTable('users').onDelete('CASCADE');
    t.timestamp('authTime', { useTz: true });
    t.timestamp('expiresAt', { useTz: true }).notNullable().index();
    t.boolean('finished').notNullable().defaultTo(false);
  });
};
exports.down = async (knex) => {
  for (const table of ['oauthInteractions', 'oauthSessions', 'oauthCredentials', 'oauthGrants', 'oauthClients']) {
    await knex.schema.dropTable(table);
  }
};
