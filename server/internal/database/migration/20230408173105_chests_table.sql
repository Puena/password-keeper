-- +goose Up
-- +goose StatementBegin
CREATE TABLE chests (
  id text not null,
  user_id uuid not null,
  salt bytea not null,
  name text not null,
  data bytea not null,
  data_type integer not null,
  primary key (user_id, id),
  foreign key (user_id) references users(id)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS chests;
-- +goose StatementEnd
