# GitHub のコネクタ

関所の GitHub のコネクタが、GitHub の API と git の HTTP の要求をどう読み、どの操作に揃え、何を断るかを決める。コネクタを置くこと・部品の分け方・読みを通すこと・mutation の形を限ること・マージを head の SHA に結び付けることは ADR-0005 が決め、細部（引き直す対象の型、上流への問い合わせの形、見分けられない push の出し方、対応の形式）をこの文書と [振り分けの形式](routes.md) に委ねている。

## どの宛先で働くか

- 振り分けで `github` の節を持つ宛先の要求は、すべてこのコネクタが読む。節の書き方は [振り分けの形式](routes.md) の「github」にある。
- 1 つの宛先の中で、要求の形で読み方を分ける。

| 要求 | 読み方 |
|---|---|
| `GET`・`HEAD` | 読み。表を見ずに通す |
| `POST` で path が `/git-upload-pack` で終わる | git の取り込み（fetch・clone）。読みとして通す |
| `POST` で path が `/git-receive-pack` で終わる | git の push（下の「git の push」） |
| `POST /graphql` | GraphQL（下の「GraphQL」） |
| そのほか | REST の書き（下の「REST の書き」） |

- 読みとして通した要求も、ほかの要求と同じく記録に残る（ADR-0006）。
- 操作に揃えたものは、表（`operations` と宛先の `default`）で allow・ask・deny を決める。コネクタが自分で断るのは、要求を下の形に読めないときだけである。その断りは表では変えられないので、本文に表の案内は書かない（[関所の応答](gate-responses.md)）。

## REST の書き

- 宛先の `rules` で、method・path と、要るときは本文の欄から操作に揃える。どの規則にも当たらなければ生の操作になる。
- 引数の `owner` と `repo` は小文字に揃える。GitHub は大文字と小文字を区別しないためである。
- 次の 2 つは GitHub の決まりとして、コネクタが規則に加えて読む。

| 要求 | コネクタがすること |
|---|---|
| `PUT /repos/{owner}/{repo}/pulls/{number}/merge` | 本文の `sha`（文字列）を引数 `sha` にする。本文を JSON として全部読めない、`sha` が無い・空・文字列でないときは断る |
| `POST /repos/{owner}/{repo}/git/refs` で、本文の `ref` が `refs/tags/` で始まり `sha` がある | tag の事実（下の「tag の事実」）を引いて足す |

- マージの規則には、本文の `sha` を引数に取る欄（`body: {sha: "{sha}"}`）を書いておく。先に頼む口でマージを頼むときに、`sha` も引数として求めるためである（[承認の口](approvals-api.md)）。

## GraphQL

### 文書の形

本文は JSON の 1 つのオブジェクトで、`query`（文書）と、あれば `variables` と `operationName` を持つ。文書は既存の GraphQL の parser（gqlparser）で、schema を使わずに解く。形だけを見れば足り、schema は GitHub のものだからである。

| 文書 | 扱い |
|---|---|
| operation がすべて query | 読みとして通す |
| mutation が 1 つだけで、ほかの operation が無く、いちばん上の選びが欄 1 つ（fragment でない） | その欄を操作に揃える（下） |
| subscription がある | 断る |
| mutation と、ほかの operation（mutation でも query でも）がある | 断る |
| mutation のいちばん上の欄が 2 つ以上、または fragment | 断る |
| 文書を解けない、operation が無い、`query` が無い | 断る |
| 本文が JSON の 1 つのオブジェクトでない（配列で束ねたものを含む）、どこかのオブジェクトに同じ欄が 2 度ある | 断る |
| 本文が記録の本文の上限（振り分けの `bodyLimitBytes`）より長く、全部を読めていない | 断る |

- 同じ欄が 2 度ある本文を断るのは、関所と GitHub が違う値を読むおそれがあるためである。
- query と同じ文書に mutation を置けないのは、ADR-0005 の「mutation が 2 つ以上」より狭い。`operationName` でどちらが動くかを関所が確かめずに済ませるためである。

### 欄の引数

- 欄の引数と、引数 `input` のオブジェクトの中の欄を、どちらも引数として読む。GitHub の mutation は引数を `input` にまとめているからである。
- 変数は `variables` の値で置き換える。`variables` に無い変数は、文書に書かれた既定の値で置き換える。
- 文字列・数・真偽は、文字列として比べる。

### 対象の引き直し

- 名前が `Id` で終わる引数（`clientMutationId` を除く）で、値が文字列のものを node ID として、上流に引き直す。ID の並び（`labelIds` など）は対象ではないので引かない。
- 引き直しは、固定の 1 つの問い合わせで、node ID ごとに型と、人が読める事実を引く。引ける型と、そこから作る引数と事実は次のとおりである。

| 型 | 引数 | 事実 |
|---|---|---|
| `Repository` | `owner`・`repo` | |
| `PullRequest` | `owner`・`repo`・`number` | `head`（head の SHA） |
| `Issue` | `owner`・`repo`・`number` | |
| `IssueComment` | `owner`・`repo`・`number`・`comment` | |
| `PullRequestReview` | `owner`・`repo`・`number`・`review` | |
| `PullRequestReviewComment` | `owner`・`repo`・`number`・`comment` | |
| `PullRequestReviewThread` | `owner`・`repo`・`number` | |
| `Ref` | `owner`・`repo`・`ref` | `commit` |
| `Commit` | `owner`・`repo`・`commit` | |
| `Label` | `owner`・`repo`・`label` | |
| `User` | `user` | |
| `Organization` | `org` | |

- `owner`・`repo`・`user`・`org` は小文字に揃える。`comment`・`review` は GitHub の数の id である。
- 引数は照合に使い、事実は承認の画面と記録に出すだけで照合には使わない（[承認の口](approvals-api.md)）。
- 引き直せない node ID は断る。上流がその ID を返さない（null）とき、上の表に無い型のとき、答えに要る欄が欠けているときである。上流が答えないとき（つながらない、200 でない）も断る。
- node ID が 2 つ以上あるときは、もっとも細かい型（コメント・レビューの類 → PR・issue → ref・commit・label → リポジトリ → 人・組織）を、mutation が向かう主の対象にする。同じ細かさなら引数の名前が短いもの、それも同じなら名前の順で決める。主の対象の引数はそのままの名前で、ほかの node ID の引数は、引数の名前から `Id` を除いたものと `_` を前に付けて並べる（例: `createPullRequest` の `headRepositoryId` は `headRepository_owner`・`headRepository_repo`）。

### 操作の名前と引数

- 欄の名前は、宛先の `github` の節の `graphql` の規則で操作に揃える。どの規則にも当たらない欄は、`graphql.` に欄の名前を付けた操作（例: `graphql.addStar`）として扱い、表に行が無ければ宛先の既定で決まる。生の操作にしないのは、生の操作の期限付きの許しが同じ method と path に効き、`POST /graphql` のすべての mutation を通してしまうためである。
- 次の欄は GitHub の決まりとして、コネクタが引数を足す。

| 欄 | 足す引数 | 断るとき |
|---|---|---|
| `mergePullRequest`・`enablePullRequestAutoMerge` | `sha`（`expectedHeadOid`） | `expectedHeadOid` が無い・空 |
| `createRef` | `ref`（`name`）・`sha`（`oid`） | |
| `updateRef` | `sha`（`oid`） | |

- `createRef` の `name` が `refs/tags/` で始まるときは、tag の事実を引いて足す。
- 引数の並びは、主の対象の引数、上の表で足す引数、ほかの node ID の引数、規則の `args`・`on` が取った引数の順である。
- 対象は、規則の `target` があればそれ、無ければ主の対象の引数と規則が取った引数である。REST と同じ操作は、同じ引数の名前と同じ対象になるように書く（マージなら `owner`・`repo`・`number`）。

## git の push

### 命令の並びを読む

- path は `/{owner}/{repo}/git-receive-pack` で、`repo` の末尾の `.git` は除く。`owner` と `repo` は小文字に揃える。この形でなければ断る。
- 本文の先頭の pkt-line を、最初の flush（`0000`）まで読む。先頭の `shallow` の行は飛ばす。最初の命令の NUL から後（capability）は読まない。flush の後の pack は読まない。
- 次のときは断る。`Content-Encoding` がある（`identity` を除く）、flush までの命令を関所が読んだ本文の中に読めない、行が「古い SHA・新しい SHA・ref」の形でない、SHA が 40 桁か 64 桁の小文字の 16 進でない、ref が `refs/` で始まる名前でない、古い SHA と新しい SHA がどちらも 0、同じ ref が 2 度ある、命令が 1 つも無い、push の証明（`push-cert`）。
- 命令の並びは pack の手前にあるので、記録の本文の上限（`bodyLimitBytes`）を超える push でも、上限の中に flush まであれば読める。上限を 0 にすると push はすべて断られる。

### ref ごとの操作

ref ごとに、変え方の種類を決める。

| 種類 | とき |
|---|---|
| `create` | 古い SHA が 0 |
| `delete` | 新しい SHA が 0 |
| `update` | どちらも 0 でなく、上流が「新しい commit は古い commit の続き」と答えたか、答えられなかった |
| `force` | どちらも 0 でなく、上流が「続きでない」と答えた |

- 宛先の `github` の節の `pushes` の規則で、種類・リポジトリ（`owner/repo`）・ref から操作に揃える。どの規則にも当たらない ref は生の操作になる。
- 引数は `owner`・`repo`・`ref`、規則の `repository`・`ref` が取った引数、`delete` でなければ `sha`（新しい SHA）の順である。対象は `owner`・`repo`・`ref` である。
- 事実は `kind`（種類）、`update` と `force` では `old`（古い SHA）と `fastForward`（`yes`・`no`・`unknown`）、`delete` では `old`、tag の `create` では tag の事実である。
- 1 回の許しの照合に使う指紋は、ref ごとに、向け直し元・宛先・ポート・path と、その ref の命令の行から作る。pack は作るたびに同じとは限らないので、指紋に入れない。

### force push の見分け方

- `update` の命令ごとに、上流に `compare`（古い SHA...新しい SHA）を問い合わせる。答えの `status` が `ahead` か `identical` なら続き、`behind` か `diverged` なら force push である。
- **新しい commit が push の pack の中にしか無いとき（ふつうの push と、新しい commit を作り直した force push）、上流はまだそれを知らず、404 を返す。** このときは見分けられないので、`update` とし、事実の `fastForward` を `unknown` にする。上流が新しい commit を知っているとき（前の commit への巻き戻し、すでにある commit への付け替え）だけ、force push と見分けられる。
- pack を読めば見分けられるが、pack の中身は読まない（ADR-0005）。守っている branch の force push を確かに止めるのは、GitHub の側の ruleset である（ADR-0005 の Decision「床は GitHub の側にある」）。
- したがって、表の `kinds: [force]` の規則（守っている branch への force push の deny など）は、force push と見分けられたときにだけ当たる。履歴を書き換えた force push は `update` として表を引く。machine account が自分で作ったリポジトリには ruleset が無いので、そこでの履歴の書き換えは関所では止まらない（ADR-0005 の Decision「git の push」）。

### 1 回の push に ref が複数あるとき

- ref ごとの操作のうち、表が deny のものが 1 つでもあれば、push の全体を断る。
- deny が無く、ask の操作がすべて台帳の許しに当たれば、push を通す。表が allow の操作は台帳を見ない。
- ask の操作のうち許しに当たらないものがあれば、それらをまとめて 1 つの承認待ちにする（承認待ちの `items` に ref ごとに 1 つ）。許しに当たったものは承認待ちに入れない。push は通さない。
- 1 回の許しは、push の全体が通るときにだけ使われる。一部の ref だけ許しがあって push が通らないときは、その許しは残る。
- git の push は 1 つの要求なので、一部の ref だけを通すことはできない。全部を通すか、全部を通さないかである。
- 記録の操作と対象は、ref ごとの操作の名前を `, ` で、対象を `; ` でつないだものになる。

## tag の事実

tag を作る要求（REST の `git/refs`、GraphQL の `createRef`、push の `refs/tags/` の `create`）には、本人が判断するための事実として次を足す。

| 事実 | 中身 |
|---|---|
| `commit` | tag を付ける SHA |
| `defaultBranch` | リポジトリの default の branch |
| `onDefaultBranch` | その SHA が default の branch にあるか。`true`・`false`、上流がその SHA を知らなければ `unknown` |

- default の branch はリポジトリを問い合わせて引き、あるかどうかは `compare`（default の branch...SHA）の `status` が `behind` か `identical` かで決める。
- リポジトリを上流が知らないときは断る。上流が答えないときも断る。
- 注釈付きの tag を git で push すると、tag の object は pack の中にしか無いので、`onDefaultBranch` は `unknown` になる。
- release の作成（REST の `releases`）も tag を作りうるが、この版では tag の事実を足さない。規則で操作に揃え、表で決める。

## 関所の問い合わせ

- 引き直しと見分けの問い合わせは、宛先の `github` の節の `api` の名前（省けば宛先そのもの）のポート 443 へ、authd を通して送る（ADR-0003 の Decision「関所自身の問い合わせも authd を通す」）。
- 問い合わせには、要求に付いていた `Authorization` をそのまま付ける。サロゲートのまま渡し、authd が本物に差し替える。問い合わせは、要求を出した身元の権限を超えない。
- そのため authd の登録で、そのサロゲートの `upstreams` に `api` の名前を入れ、置き場所にその道具の付け方を入れておく。git は `Authorization` の Basic のパスワードにサロゲートを置くので、git の宛先の問い合わせ（force push の見分けと tag の事実）は、API の名前へ Basic のまま送られる（[authd の登録の形式](authd-registration.md)）。
- 問い合わせは、送る前に記録（kind が `gate`）に書く。書けなければ問い合わせず、要求も通さない。記録の `source` は要求を出した向け直し元で、`reason` は何のための問い合わせか、本文は GraphQL の問い合わせ（node ID を含む）である（[関所の記録](audit.md)）。
- 答えは 1 MiB まで読む。引き直した結果は覚えず、要求のたびに問い合わせる。

## この版で扱わないもの

- 判定器で本文（コメント・PR の本文など）を見ること。
- GitHub Enterprise Server のように GraphQL の path が `/graphql` でない宛先。
- ID の並び（`labelIds` など）の引き直し。
- 先に頼む口で、REST の規則の無い操作（GraphQL の欄の規則と push の規則だけが名付けている操作）を頼むこと。先に頼む口は REST の規則の引数で頼む（[承認の口](approvals-api.md)）。
