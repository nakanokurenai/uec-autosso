socks5test
===

server
---

```sh
go run .
```

client
---
- Firefox の証明書ストアに cacert.der をインポートして信頼
- Firefox のネットワーク設定から「SOCKS ホスト」に `localhost:1080` を設定し「SOCKS v5 を使用するときは DNS もプロキシーを使用する」にチェック
- `https://thissitedoesnotexist.example.com` を開くと動く、動く
