# 0005. GitHub の操作は、REST も GraphQL も透過で解いて表で決める

- Date: 2026-11-09
- Updated: 2026-11-13（対象の引き直しの問い合わせを、次の版から関所が送ることを足した。ADR-0007）
- Status: Accepted

## Context

運用の係（クラスタの運用を受け持つ natsumi のインスタンス）は、GitHub の machine account で、fork からの PR・issue・コメント・レビュー、fork と自分の private のリポジトリへの push、限られたリポジトリのマージと tag をする。
今は中継のスクリプトが、次の形で判定している。

- REST の書き込みは、method と path と本文の欄を、許可リストの正規表現と全体一致で確かめる。当てはまらなければ 403。自分の private のリポジトリの作成は、本文の `private` が true のときだけ通す。
- GraphQL は全部断る。machine account の token は招かれたリポジトリへの書き込みを何でもでき、GraphQL の文書の中身を中継で確かめられないためである。そのため GraphQL を使う道具は動かない。道具の手引きは「`gh pr merge` は GraphQL なので使えない。REST の API を使う」と案内している。
- git の push は、`git-receive-pack` の本文の先頭の命令の並び（古い SHA・新しい SHA・ref）を読み、自分の fork と private のリポジトリへの push だけを通す。ref の削除と、守っている branch（default の branch など）への push は断る。pack の中身は読まない。
- マージと tag は、マージの許可リストのリポジトリでだけ通し、本人の ok は会話の中で取る。中継はその ok を確かめられない。tag は、その commit が default の branch にあるときだけ通す。

本人は、運用で何を許すかを柔軟にしたい。GraphQL で監査できないために許せていない操作も、許せるようにしたい。

GitHub の GraphQL の操作は query と mutation の 2 種類である。mutation の意味は、文書のいちばん上の欄の名前と引数で決まり、その下の欄は戻り値の選び方で、読みでしかない。

## Decision

### GitHub の API と git は開く宛先にし、コネクタで操作に揃える

- GitHub の API と git の HTTP の宛先は開く宛先（ADR-0002 の Decision「扱いは宛先ごとに 3 つ」）にし、規則に当たらない要求の既定を ask にする（ADR-0004 の Decision「宛先ごとの既定と規則で、allow・ask・deny を決める」）。
- 要求を操作に揃えるのは、関所のプロセスの中の GitHub のコネクタである。道具はふつうに GitHub に話し、関所は通信の側で要求を読む。道具は `gh` と git をそのまま使う。
- コネクタの部品は 3 つに分ける。

| 部品 | 中身 | どこに持つか |
| --- | --- | --- |
| ① 文書を解く | GraphQL の文書を解き、operation の種類と、mutation のいちばん上の欄と引数を取り出す | 関所のコード（GitHub に固有でない。既存の GraphQL の parser を使う） |
| ② 要求 → 操作 | REST の method・path と、GraphQL の mutation の欄の名前を、操作の名前に対応させる | 仕組みは関所のコード、対応は表のデータ（環境のリポジトリ） |
| ③ 対象の引き直し | 要求の引数（node ID、PR の番号）から、リポジトリ・番号・head の SHA などの人が読める事実を上流に問い合わせて引く | 関所のコード（GitHub に固有。対象の型ごとの固定の問い合わせ） |

- 操作を足すのは、② の対応の 1 行で済む。関所のコードを変えるのは、③ で引き直せない対象の型が出たときだけである。
- ③ の問い合わせは、要求を出した身元のサロゲートで、authd を通して送る（ADR-0003 の Decision「関所自身の問い合わせも authd を通す」）。関所の問い合わせとして記録に残す（ADR-0006）。
  - 次の版から、③ の問い合わせも、要求を出した身元のサロゲートで authd から本物の鍵を受け取り、関所が送る（2026-11-13、ADR-0007 の Decision「移す順番」）。身元と記録の決まりは変えない。

### REST

- 読み（GET と HEAD）は通し、記録する（ADR-0006 の Decision「何を残すか」）。
- 書きは、method と path（と、要るときは本文の欄）から ② で操作に揃え、表で決める。対象は path に出るもの（リポジトリ、PR や issue の番号、ref など）で、要るときは ③ で事実を足す。

### GraphQL

- 文書の operation が全部 query なら、読みとして通して記録する。`gh` の読みのコマンドが使えるようになる。
- mutation は、1 つの文書に mutation が 1 つで、そのいちばん上の欄も 1 つのときだけ扱う。
  - その欄の名前を ② で操作に揃え、表で決める。
  - 対象は、引数の node ID を ③ で引き直した事実（リポジトリ・番号・head の SHA など）にする。表・台帳・承認の画面に出すのは、引き直した事実であって、引数の ID ではない。運用の係が偽の node ID を渡しても、画面には関所が引いた本当の対象が出る。
  - ② の対応に無い欄は、欄の名前を持つ生の操作として ask にする（ADR-0004 の Decision「決めていないものは本人に聞く」）。
- 次のものは断る。mutation が 2 つ以上、いちばん上の欄が 2 つ以上、subscription、文書を解けない、③ で対象を引き直せない。断るときは、本文に理由を書く。

### git の push

- push は、`git-receive-pack` の命令の並びを読み、ref ごとに操作に揃えて表で決める。対象はリポジトリと ref。
- ref の作成・更新・削除を見分ける（命令の古い SHA と新しい SHA のどちらかが 0 か）。force push かどうかは、③ で上流に問い合わせて見分ける。
- 上流への問い合わせで force push と見分けられるのは、新しい SHA が上流のすでに知っている commit のとき（巻き戻し、ほかの branch の commit への付け替え）だけである。新しく送る commit は、問い合わせの時点では pack の中にあって上流に無い。そのため rebase や amend で履歴を書き換えた force push は、ふつうの更新と区別できない。見分けられない push は更新として表を引き、承認の画面には fast-forward かどうか分からないことを事実として出す。
- pack の中身は読まない。命令の並びを読めなければ断る。
- 取り込み（fetch・clone）は読みとして通す。

### マージと tag

- PR のマージと tag の作成は ask にする。REST でも GraphQL でも、同じ操作の名前で表を引く。
- 運用の係は、マージする PR の一覧（番号・題・head の SHA）を、1 回の許しの束として先に頼める（ADR-0004 の Decision「先に頼めるのは、具体的な操作と対象の一覧だけ」）。
- マージの許しは、PR ごとに head の SHA に結び付ける。承認の後に head が動けば、許しは当たらない。
- 関所が確かめてから上流がマージするまでにも head は動きうるので、マージの要求には head の SHA を必ず載せさせ、上流にも確かめさせる。SHA を載せないマージの要求は断る。
- tag の承認の画面には、tag を付ける commit と、それが default の branch にあるかを、③ で引いた事実として出す。今の中継の確かめを、本人の判断の材料に移す。
- 会話の中の ok は数えない。

### 最初の表

- 今の中継の許可リストに当たる操作（fork の作成、fork からの PR・issue・コメント・レビュー、自分の fork と自分の private のリポジトリへの push）は allow にする。
- 自分のリポジトリの作成は、private で作るときだけ allow にする。public で作る作成と、公開範囲の変更は deny にする。
- PR のマージと tag の作成は ask にする。
- 今まで床として断っていた種類は deny にする。ref の削除、守っている branch への force push、`/user` 系（自分の private のリポジトリの作成を除く）、Actions の secrets と variables、webhook、deploy key、リポジトリの設定・collaborator・公開範囲。
  - 守っている branch への force push の deny は、上の「git の push」で force push と見分けられる場合にだけ効く。守っている branch を確かに守るのは GitHub の ruleset である（下の「床は GitHub の側にある」）。
  - どれも表のデータなので、環境のリポジトリの変更で ask に変えられる（ADR-0004 の Decision「決めていないものは本人に聞く」）。
- 上のどれにも当たらない書きは、宛先の既定の ask になる。

### 床は GitHub の側にある。ただし自分のリポジトリには無い

- machine account は、本人のリポジトリには write の collaborator として招く。リポジトリの設定・collaborator・公開範囲の変更には admin が要るので、表を誤って緩めてもできない。
- 運用の係の閉じ込めを決めるリポジトリ（natsumi、関所の配置を持つ環境のリポジトリなど）には、書き込みの権限を渡さない。Approve までで、マージは本人がする。
- 守っている branch は、GitHub の ruleset でも守る。
- **machine account が自分で作ったリポジトリでは、machine account 自身が管理者である。** 公開範囲・deploy key・webhook・secrets の変更は GitHub の側では止まらず、表の deny だけが頼りになる。
- 自分で作ったリポジトリには ruleset の床も無い。そこで履歴を書き換える force push は、関所が見分けられないので止まらない。これは受け入れる。

### 守る対象と、倒す向き

- 守るのは、GitHub の書きが表と台帳に沿ったものだけ届くことと、マージと tag が本人の承認なしに通らないことである。
- 許す範囲は、REST と GraphQL の読み、表の allow、台帳の許しに当たる書きである。
- 文書を解けない、上の形に当たらない mutation、命令の並びを読めない、対象を引き直せない、上流への問い合わせに失敗したときは、断る側に倒す。

### 本 ADR で決定しないこと

- 操作の名前の一覧と、REST の method・path と GraphQL の欄の名前から操作への対応（委譲先: 環境のリポジトリの運用の係の設定）。対応の形式（委譲先: 関所の設定の仕様書）。
- ③ で引き直す対象の型と、それぞれの問い合わせ（委譲先: 関所の実装の PR）。
- 上流への問い合わせの形と、見分けられない push を承認の画面にどう出すか（委譲先: 関所の GitHub のコネクタの仕様書）。
- 書きを許すリポジトリと、マージを許すリポジトリの一覧（委譲先: 環境のリポジトリの運用の係の設定と、GitHub の collaborator の設定）。
- 道具の手引きで、マージに head の SHA を載せる使い方を案内すること（委譲先: 環境のリポジトリの運用の係の手引き）。
- 判定器で GitHub の本文（コメント・PR の本文など）を見ること（委譲先: 判定器を入れる版の ADR）。

## Consequences

- `gh` の読みも書きも、ふつうに使える。書きは表に沿って通るか、聞かれるか、断られる。REST の API に書き直して使う手間が無くなる。マージだけは、head の SHA を載せる使い方に限られる。
- REST と GraphQL の同じ操作（マージなど）を、1 つの表で引ける。操作を足すのは対応の 1 行で、関所のリリースは要らない。
- マージと tag は本人の承認で通り、head の SHA に結び付くので、承認の後に積まれた commit は通らない。会話で ok を偽っても通らない。
- 承認の画面に出る対象は関所が引き直した事実なので、偽の node ID で別の対象を書かせることはできない。
- ③ の問い合わせのぶん、GraphQL の書きのたびに上流への読みが増え、少し遅くなる。
- 規則に当たらない書きは断られずに聞かれる。最初のうちは聞かれる回数が多い。
- 1 つの文書に複数の mutation を入れる道具は動かない。
- 床は GitHub の側の権限と ruleset である。表を誤って緩めれば、machine account の権限の範囲の書きは通る。自分で作ったリポジトリでは、表の deny のほかに止めるものが無い。
- 履歴を書き換える force push は、ふつうの更新と区別できない。守っている branch では GitHub の ruleset が止める。自分で作ったリポジトリでは止まらない。代わりに、関所は pack を読まずに済む。
- GraphQL の読みを通すので、読める範囲は machine account が読める範囲すべてになる。読みは記録に残る（ADR-0006）。

## Alternatives Considered

- **GraphQL を今どおり全部断る**: `gh` の多くのコマンドが使えず、GraphQL でしかできない書きも許す道が無い。
- **GraphQL の書きを、作業環境向けの口で名前と引数で受け、関所が固定の文書を代わりに送る（操作の定義）**: GitHub の書きの道が、透過の REST と、関所が代わりに実行する道の 2 本になる。設定で書く小さな言語（引数の型・値を引く問い合わせの型・文書）とその実行器を関所に持つことになり、ADR-0001 の Decision「Muse と違えるところ」の「privsep は取らない」とも食い違う。`gh` の書きも動かないままで、操作を足すたびに本人が文書をレビューする負担が続く。mutation を 1 つの文書に 1 つ・いちばん上の欄も 1 つに限れば、任意の文書から対象を確かめる難しさは無くなり、対象は ③ で引き直せる。
- **GraphQL の文書を任意の形のまま中身で判定する**: どの mutation がどの対象に何をするかを、任意の文書から確かめるのは難しい。形を限れば足りる。
- **pack の中の commit を関所が読み、新しい commit から親をたどって force push を見分ける**: 見分けは確かになるが、敵意のある入力を解く関所に pack の読み取り（圧縮の展開と object の解析）を持ち込む。「pack の中身は読まない」を保ち、確かな守りは GitHub の ruleset に任せる。
- **承認の画面に引数の node ID をそのまま出す**: node ID は人が読めず、偽った node ID で別の対象を書ける。
- **マージの ok を会話の中で取り続ける**: 関所が確かめられず、乗っ取られた運用の係が ok を偽れる。会話の ok で済ませたのは、確かめる仕組みが無かったためで、関所が入ればその前提が無くなる。

## Related ADRs

- Related: ADR-0001 作業環境の外に関所と鍵の番を分けて置き、鍵の要る操作を判定と記録に通す
- Related: ADR-0002 作業環境の外向きの通信を透過で関所に通し、宛先ごとに扱いを決める
- Related: ADR-0003 道具にはいつもサロゲートを持たせ、authd だけが本物に差し替えて送る
- Related: ADR-0004 宛先ごとの規則で決め、決めていないものは本人に聞き、範囲付きの許しを台帳に残す
- Related: ADR-0006 出ていくものを関所の記録に残し、いつもと違うことを知らせる
- Related: ADR-0007 関所が判定して自分で上流へ送り、authd は鍵を保管して要求ごとに渡す（対象の引き直しの問い合わせの送り方を、次の版から改める）

## References

- 環境のリポジトリ（private）の運用の係の中継のスクリプト `relay/relay.js` の `githubApiWrite`（REST の書き込みの許可リスト、`/user/repos` は `private` が true のときだけ）・`mergeOrTag`・`onDefaultBranch`（マージの許可リスト、tag の commit が default の branch にあるかの確かめ）・`receivePack`（push の命令の並びを読み、ref の削除と守っている branch への push を断る）、冒頭の説明（GraphQL を断る理由）、2026-11-09 確認
- 環境のリポジトリ（private）の運用の係の手引き `tools/README.md`（マージと tag は本人が会話で ok したものだけ、`gh pr merge` は GraphQL なので使えない）、2026-11-10 確認
- Git「pack-protocol」の `git-receive-pack` の命令の並び（create は古い SHA が 0、delete は新しい SHA が 0。https://git-scm.com/docs/pack-protocol 、2026-11-09 確認）
- 関所の GitHub のコネクタの仕様書 `docs/github.md` の「force push の見分け方」（見分けられない push は更新とし、事実の `fastForward` を `unknown` にする）、2026-11-11 確認
- GitHub Docs「Compare two commits」（`GET /repos/{owner}/{repo}/compare/{basehead}` の `status` は ahead・behind・identical・diverged で、応答に 404 Resource not found がある。https://docs.github.com/en/rest/commits/commits#compare-two-commits 、2026-11-11 確認）
- GitHub Docs「Forming calls with GraphQL」（GitHub の GraphQL の操作は query と mutation の 2 種類、https://docs.github.com/en/graphql/guides/forming-calls-with-graphql 、2026-11-09 確認）
