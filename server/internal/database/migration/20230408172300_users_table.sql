-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
  id uuid not null primary key,
  login text not null,  -- because this is distributed table by id, we cannot do this field trully unique. We need check unique mannually.
  password text not null,
  created_at timestamp not null
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
