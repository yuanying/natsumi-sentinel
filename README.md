# natsumi-sentinel

A Sentinel-like gate for natsumi's workspace: transparent egress proxy, surrogate credentials, scoped approvals and audit.

natsumi-sentinel は、[natsumi](https://github.com/yuanying/natsumi) のインスタンスの作業環境から外へ出る通信を見張る、関所（sentinel）と鍵の番（authd）の 2 つのプログラムです。
同じ Pod の中の別のコンテナとして動き、作業環境の通信を透過で受けて宛先ごとに扱いを決め、操作の表で allow・ask・deny を判定し、決めていない操作は本人に聞いて範囲付きの許しを台帳に残します。
道具には本物の鍵の代わりにサロゲートを持たせ、authd だけが登録した宛先で本物に差し替えて送ります。出ていくものはすべて記録し、指標と知らせで異常に気づけるようにします。

設計の判断は [docs/adr/](docs/adr/) にあります。

## 作り方

入口は `Makefile` です。`make help` でターゲットの一覧が出ます。必要なのは Go のツールチェーンだけで、lint と脆弱性の検査の道具は `go.mod` の `tool` から `go tool` で動きます。

| コマンド | すること |
|---|---|
| `make help` | ターゲットの一覧を出す |
| `make build` | `bin/sentinel` と `bin/authd` を作る |
| `make test` | 単体テストを走らせる |
| `make test-netns` | iptables で本物の接続を向け直すテストを、sudo で使い捨ての network namespace の中で走らせる |
| `make fmt-check vet lint tidy vuln` | CI と同じ検査をする |
| `make dist` | 2 つのバイナリを linux/amd64・linux/arm64 の archive にして `dist/` に置く |

どちらのバイナリも `--version` で版を出します。authd の登録の形式は [docs/authd-registration.md](docs/authd-registration.md)、関所と authd の間の形は [docs/authd-protocol.md](docs/authd-protocol.md) にあります。

関所は `-check -config <ディレクトリ>` で振り分けを確かめられます。開く宛先の要求は `-authd-socket` の authd へ渡します。authd へは最初の要求のときにつなぎ、つながらないあいだは、その要求を通しません。振り分けの形式は [docs/routes.md](docs/routes.md)、関所が返す応答とその印は [docs/gate-responses.md](docs/gate-responses.md)、記録の欄は [docs/audit.md](docs/audit.md) にあります。

image は 1 つの `Dockerfile` から、target を選んで作ります。

| image | target | プログラム |
|---|---|---|
| `ghcr.io/yuanying/natsumi-sentinel` | `sentinel` | 関所 |
| `ghcr.io/yuanying/natsumi-sentinel-authd` | `authd` | 鍵の番 |

`vX.Y.Z` の tag を push すると、2 つの image が linux/amd64・linux/arm64 で ghcr.io に出て、GitHub Release ができます。

## License

MIT
