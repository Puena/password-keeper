-- +goose Up
-- +goose StatementBegin
CREATE TABLE history (
  id text not null,
  user_id uuid not null,
  chest_id text not null,
  operation_type integer not null,
  operation_time timestamp not null,
  syncing_time timestamp not null,
  device_name text not null,
  device_ip text not null,
  primary key(user_id, chest_id, id)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS history;
-- +goose StatementEnd
