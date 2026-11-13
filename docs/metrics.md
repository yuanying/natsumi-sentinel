# 指標

関所（`sentinel`）と authd が出す Prometheus の指標の名前と label を決める。指標を出すこと、少なくとも何を出すか、止まったことに外から気づくことは ADR-0006 の Decision「指標を出し、止まったことに外から気づく」が決め、名前と label をこの文書（と実装）に委ねている。

## 待ち受け

| プログラム | フラグ | 省略したとき |
|---|---|---|
| 関所 | `-metrics-listen` に TCP の待ち受けの場所（`127.0.0.1:9090`、`:9090` の形） | 指標を出さない |
| authd | `--metrics-listen` に同じ形 | 指標を出さない |

- 指標は、その場所の `/metrics` に Prometheus の text の形で出る。ほかの path は 404 である。
- 場所を与えたのに待ち受けられなければ、そのプログラムは起動しない（設定が使えなければ起動しない、ADR-0001）。
- 待ち受けに認証は無い。指標には鍵・token・サロゲートの値も、作業環境が自由に決められる値も入らないので、読まれて困るものは無い。同じ Pod の作業環境からも読めることを前提にしている。

## label の決まり

- label には、値の数が決まっていて小さいものだけを使う。作業環境が自由に決められる値（path、query、振り分けに無い名前、passthrough の IP など）は label にしない。series の数を作業環境が増やせないようにするためである。
- 宛先の名前（`destination`）は、本人が決めた名前だけを label にする。振り分けにある名前と、関所の固定の名前（`-gate-name`）である。それ以外の名前は `(not-listed)` にまとめる。passthrough は名前を持たず、IP は範囲の中のどれでもありうるので、`destination` は空である。
- 理由（`reason`）は、プログラムが持つ閉じた集合の値だけを使う。新しい authd が知らない理由を返したときは `other` にまとめる。
- 理由ごと・段ごとのように値の集合が決まっている label は、起動したときから 0 で出しておく。最初の 1 回の増えも、規則の `increase` で拾える。

## 両方に共通のもの

| 名前 | 型 | label | 中身 |
|---|---|---|---|
| `sentinel_build_info`・`authd_build_info` | gauge | `version` | いつも 1。動いている版を label に持つ。動いているあいだ必ずある series で、途絶えたことの見張り（dead man's switch）に使う |
| `go_*`・`process_*` | | | Go の runtime とプロセスの指標（Prometheus の client の標準のもの） |

## 関所

| 名前 | 型 | label | 中身 |
|---|---|---|---|
| `sentinel_requests_total` | counter | `source`・`kind`・`treatment`・`destination`・`verdict` | 記録に残ったものの数。要求・接続・passthrough・名前解決・関所自身の要求 |
| `sentinel_audit_write_failures_total` | counter | `stage`（`begin`・`write`・`finish`） | 記録を書けなかった数 |
| `sentinel_routes_reload_failures_total` | counter | なし | 振り分けを読み直して採れなかった数（前の振り分けのまま動いている） |
| `sentinel_upstream_failures_total` | counter | `destination`・`reason` | 関所が通した要求で、上流の答えが得られなかった数 |
| `sentinel_approvals_pending` | gauge | なし | 本人の答えを待っている承認待ちの数。台帳から、scrape のたびに数える |
| `sentinel_destination_grants` | gauge | `handling`・`access` | 効いている宛先の許しの数（`-destination-grants` のときだけ）。台帳から、scrape のたびに数える |
| `sentinel_refused_names` | gauge | なし | 覚えている断った名前の数（`-destination-grants` のときだけ） |
| `sentinel_refused_names_dropped_total` | counter | なし | 上限で覚えから落とした断った名前の数 |
| `sentinel_refused_names_unkept_total` | counter | なし | 覚えを書けなかった断った名前の数。名前は変わらず断った |
| `sentinel_notices_total` | counter | `type`（`first-seen`・`answer`・`daily-summary`） | 作った知らせの数。送れたかどうかによらない |
| `sentinel_notice_send_failures_total` | counter | なし | 待っている知らせを送ろうとして送れなかった回数。送り直す |
| `sentinel_notices_pending` | gauge | なし | 送るのを待っている知らせの数 |
| `sentinel_notices_dropped_total` | counter | なし | 待ちが上限を超えて、送らずに捨てた知らせの数 |
| `sentinel_notice_records_unchecked_total` | counter | なし | 「初めて見る」かを確かめられなかった記録の数。待ちが一杯だった、覚えを書けなかった |
| `sentinel_notice_summary_failures_total` | counter | なし | 1 日のまとめを記録から作れなかった数 |
| `sentinel_notice_sender_configured` | gauge | なし | 知らせを Alertmanager へ送っていれば 1、標準エラーに出すだけなら 0 |

### `sentinel_requests_total` の label

| label | 値 |
|---|---|
| `source` | 向け直し元の待ち受けの名前（`-source` の `name`）。関所自身の要求は空 |
| `kind` | 記録の `kind`。`http`・`connection`・`passthrough`・`dns`・`gate`。振り分けの読み直し（`config`）は数えない |
| `treatment` | 記録の `treatment`。`open`・`passthrough`・`deny`、当てはまらなければ空 |
| `destination` | 上の「label の決まり」のとおり |
| `verdict` | 記録の `verdict`。どう決めたか。`allow`・`ask`・`deny`。許しに当たって通ったものは `allow`。開く宛先へ張られたまま何も送られずに閉じた接続は `kind` が `connection` で `allow` である（[関所の記録](audit.md) の「接続の記録」） |

- 数えるのは、記録を書き終えたときである。上流へ渡す前に書く記録（[関所の記録](audit.md)の「書く時」）は、答えを流し終えて書き足したときに 1 つ数える。
- 記録を書けずに通さなかったものは数えない（それは `sentinel_audit_write_failures_total` に出る）。
- deny と ask の数は、`verdict` で絞って読む。

### `sentinel_approvals_pending`

- 数えるのは、台帳の承認待ちのうち、まだ答えが無く（`open`）、期限を過ぎていないものである。期限を過ぎたものは、台帳の掃除（1 分ごと）がまだ閉じていなくても数えない。
- 承認待ちにした要求も、作業環境が先に頼んだことも、1 つの承認待ちを 1 と数える。同じ要求を何度まとめても 1 である。
- 台帳が読めなかった scrape では、この series を出さない。ほかの指標は出る。規則では `absent` で拾える。

### `sentinel_upstream_failures_total` の `reason`

| 値 | 中身 |
|---|---|
| authd の理由の名前（`upstream-not-registered`・`surrogate-mismatch`・`credential-unavailable`・`bad-request`・`upstream-unreachable`・`upstream-certificate`・`upstream-failed`） | authd が断った、または上流に届かなかった。意味は [関所と authd の間の形](authd-protocol.md) の「断りと失敗の形」 |
| 関所の理由の名前（`upstream-address-local`・`upstream-address-private`・`surrogate-unswapped`・`upstream-port`・`upstream-not-https`、と失敗の 3 つ） | 関所が直に送る宛先の許しの要求・接続を、関所が断った、または上流に届かなかった。`destination` は `(not-listed)`。意味は [宛先の許し](destination-grants.md) の「呼び手に返すもの」 |
| `other` | この版が知らない理由を authd が返した |
| `authd-unreachable` | authd につなげなかった、または authd とのやりとりが壊れた |

- 上流が返した応答は、状態が 4xx・5xx でも失敗に数えない。
- 作業環境が要求の途中で去ったものは数えない。
- 関所自身の知らせの送り損ないは、ここではなく `sentinel_notice_send_failures_total` に出る。

## authd

| 名前 | 型 | label | 中身 |
|---|---|---|---|
| `authd_refusals_total` | counter | `reason`（`upstream-not-registered`・`surrogate-mismatch`・`credential-unavailable`・`bad-request`） | authd が自分の確かめで断り、上流に何も送らなかった数 |
| `authd_upstream_failures_total` | counter | `reason`（`upstream-unreachable`・`upstream-certificate`・`upstream-failed`） | 確かめを通ったが、上流の答えが得られなかった数 |
| `authd_key_read_failures_total` | counter | `credential` | 起動のとき、または使うときに、本物の鍵のファイルが読めなかった数。起動のときに読めなかった鍵は、起動の直後から 1 になる。`credential` は登録の `credentials` の中の位置（最初が `0`） |
| `authd_refused_peers_total` | counter | なし | 関所の UID でない相手からの接続を、何も読まずに閉じた数 |

- 鍵のファイルは使うたびに読み直す（[authd の登録の形式](authd-registration.md) の「鍵のファイル」）。kubelet が Secret や projected の token を作り直せなかったときは、ここに出る。
- `credential` の label には、サロゲートも鍵のファイルのパスも出さない。登録の中の位置で、どの鍵かを示す。

## ADR-0006 の項目との対応

| ADR-0006 が挙げるもの | 指標 |
|---|---|
| 要求の数（宛先・扱い・決め方ごと） | `sentinel_requests_total` |
| deny と ask の数 | `sentinel_requests_total` の `verdict` |
| 承認待ちの数 | `sentinel_approvals_pending` |
| 設定の読み直しの失敗 | `sentinel_routes_reload_failures_total` |
| 記録の書き込みの失敗 | `sentinel_audit_write_failures_total` |
| 上流への失敗 | `sentinel_upstream_failures_total` |
| 知らせの送り損ない | `sentinel_notice_send_failures_total`・`sentinel_notices_dropped_total`・`sentinel_notice_records_unchecked_total`・`sentinel_notice_summary_failures_total`・`sentinel_notice_sender_configured` |
| authd の断った数 | `authd_refusals_total`（上流への失敗は `authd_upstream_failures_total`） |
| authd の鍵の作り直しの失敗 | `authd_key_read_failures_total` |

## 知らせの規則に使うもの

規則としきい値は環境のリポジトリが持つ（ADR-0006 の「本 ADR で決定しないこと」）。ADR-0006 が関所を入れる条件とする 3 つの規則は、次の指標で書ける。

- 設定の読み直しの失敗: `sentinel_routes_reload_failures_total` が増えた。
- 記録の書き込みの失敗: `sentinel_audit_write_failures_total` が増えた。
- 知らせの送り損ない: `sentinel_notice_send_failures_total`・`sentinel_notices_dropped_total`・`sentinel_notice_records_unchecked_total`・`sentinel_notice_summary_failures_total` のどれかが増えた、または `sentinel_notice_sender_configured` が 0 である。

指標が途絶えたことは、`sentinel_build_info` と `authd_build_info` が無くなったことで分かる。
