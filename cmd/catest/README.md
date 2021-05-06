catest
===

server
---
```sh
# CA証明書が自動で生成される
go run .
```

client
---
```sh
openssl x509 -in ./cacert.der -inform DER -out cacert.pem
sock="<file>.unix"
# curl は pem 方式しか受けつけない
curl --unix-socket "$sock" --cacert ./cacert.pem -v https://hey.n11i.jp -v
```
