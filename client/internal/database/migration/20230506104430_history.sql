-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS history (
    id text not null,
    chest_id text not null,
    user_id text,
    operation_type smallint not null,
    operation_time integer not null,
    syncing_time integer,
    device_name text not null,
    device_ip text,
    foreign key (chest_id) references chests (id),
    primary key (id, chest_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE history;
-- +goose StatementEnd
