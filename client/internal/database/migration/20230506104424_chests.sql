-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS chests (
    id text not null,
    user_id text,
    salt blob not null,
    name text not null,
    data blob not null,
    data_type smallint,
    primary key(id)
)
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE chests;
-- +goose StatementEnd
