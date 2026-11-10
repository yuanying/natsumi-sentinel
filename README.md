# natsumi-sentinel

A Sentinel-like gate for natsumi's workspace: transparent egress proxy, surrogate credentials, scoped approvals and audit.

natsumi-sentinel は、[natsumi](https://github.com/yuanying/natsumi) のインスタンスの作業環境から外へ出る通信を見張る、関所（sentinel）と鍵の番（authd）の 2 つのプログラムです。
同じ Pod の中の別のコンテナとして動き、作業環境の通信を透過で受けて宛先ごとに扱いを決め、操作の表で allow・ask・deny を判定し、決めていない操作は本人に聞いて範囲付きの許しを台帳に残します。
道具には本物の鍵の代わりにサロゲートを持たせ、authd だけが登録した宛先で本物に差し替えて送ります。出ていくものはすべて記録し、指標と知らせで異常に気づけるようにします。

設計の判断は [docs/adr/](docs/adr/) にあります。

## License

MIT
