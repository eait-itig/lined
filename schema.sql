CREATE TYPE "msgtype" AS ENUM ('syslog', 'json', 'bunyan');

CREATE TABLE "messages" (
	"idx" bigserial NOT NULL,

	"saddr" inet,
	"sport" integer,
	"daddr" inet,
	"dport" integer,
	"conn" uuid,
	"seq" bigint,

	"ts" timestamptz NOT NULL DEFAULT now(),
	"id" uuid NOT NULL,
	"type" msgtype,
	"msg" bytea NOT NULL,

	"process" integer NOT NULL DEFAULT 0,
	"document" jsonb
) PARTITION BY RANGE ("ts");

CREATE INDEX "messages_idx" ON "messages" ("idx");
