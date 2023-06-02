-- +goose Up
-- +goose StatementBegin
SELECT create_distributed_table('users', 'id');
SELECT create_distributed_table('chests', 'user_id');
SELECT create_distributed_table('history', 'user_id');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT undistribute_table('users');
SELECT undistribute_table('chests');
SELECT undistribute_table('history');
-- +goose StatementEnd
