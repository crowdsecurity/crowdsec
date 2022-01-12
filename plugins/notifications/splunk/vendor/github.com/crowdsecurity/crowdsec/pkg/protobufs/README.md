To generate go code for the `notifier.proto` files, run :

```
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/alert.proto`
```

