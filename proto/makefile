src_dir = .

installreq:
	echo "start install protoc dependecies"
	go install -v google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install -v google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install -v github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
	echo "done"


protobuild:
	protoc \
	-I $(src_dir) \
	--doc_out=$(src_dir) \
	--doc_opt=markdown,README.md $(src_dir)/*.proto \
	--go_out=$(src_dir) \
	--go_opt=paths=source_relative \
    --go-grpc_out=$(src_dir) --go-grpc_opt=paths=source_relative $(src_dir)/*.proto
