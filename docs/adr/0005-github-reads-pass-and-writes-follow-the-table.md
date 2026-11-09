# 0005. GitHub の操作は、読みは解いて通し、書きは表と操作の定義で決める

- Date: 2026-11-09
- Status: Accepted

## Context

運用の係（クラスタの運用を受け持つ natsumi のインスタンス）は、GitHub の machine account で、fork からの PR・issue・コメント・レビュー、fork と自分の private のリポジトリへの push、限られたリポジトリのマージと tag をする。
今は中継のスクリプトが、次の形で判定している。

- REST の書き込みは、method と path と本文の欄を、許可リストの正規表現と全体一致で確かめる。当てはまらなければ 403。
- GraphQL は全部断る。machine account の token は招かれたリポジトリへの書き込みを何でもでき、GraphQL の文書の中身を中継で確かめられないためである。そのため `gh pr view` のように GraphQL で読む道具も使えない。
- git の push は、`git-receive-pack` の本文の先頭の命令の並び（ref・古い SHA・新しい SHA）を読み、自分の fork と private のリポジトリへの push だけを通す。ref の削除と、守っている branch（default の branch など）への push は断る。pack の中身は読まない。
- マージと tag は、マージの許可リストのリポジトリでだけ通し、本人の ok は会話の中で取る。中継はその ok を確かめられない。

本人は、運用で何を許すかを柔軟にしたい。GraphQL で監査できないために許せていない操作も、操作として許せるようにしたい。

## Decision

### GitHub の API と git は inspect にする

- GitHub の API と git の HTTP の宛先は inspect（ADR-0002）にし、GitHub のコネクタが要求を操作に揃える（ADR-0004）。
- GitHub のコネクタは関所のコードに 1 つだけ持つ。操作を足すことは、コードではなく設定（下の「操作の定義」）で行う。

### REST

- 読み（GET と HEAD）は通し、記録する（ADR-0006）。
- 書きは、method と path（と、要るときは本文の欄）から操作に揃え、表で決める。
- 表は、操作の名前と、対象（リポジトリ、PR や issue の番号、ref など）で引けるようにする。

### GraphQL は、読みだけを解いて通す

- 関所は GraphQL の文書を解く。中の operation が全部 query なら、読みとして通して記録する。`gh pr view` など、GraphQL で読む道具が使えるようになる。
- mutation か subscription が 1 つでも混ざれば断る。文書を解けないときも断る。断るときは、本文に「書きは操作で頼む」ことを書く。
- GraphQL でしかできない書きは、次の操作の定義で行う。

### 書きの操作は、レビューした定義で足す

- 関所の設定に、GitHub の書きの **操作の定義** を置く。1 つの定義は次を持つ。
  - 操作の名前と、引数の型。引数は、リポジトリの名前や PR の番号のような、人が読める名前だけにする。
  - 引数から、書きに要る値（node ID、head の SHA など）を引くための固定の問い合わせ。
  - 書きに使う固定の文書（GraphQL の mutation、または REST の要求）。
  - 表・台帳・承認の画面に出す対象。
  - 表の既定。
- 運用の係には、node ID のような人が読めない値を渡させない。関所が引数から引く。承認の画面に出す対象も、関所が引いた事実で組む（ADR-0004）。
- 定義は環境のリポジトリの設定として持ち、PR でレビューしたものだけが入る。関所は読み直し、Pod は作り直さない（ADR-0004）。
- 運用の係は、作業環境向けの口（ADR-0002）で、操作の一覧と引数の型を読み、操作を 1 つ頼める。ask なら、REST と同じく 403 と承認待ちの id を返す。
  - 道具の側は、この 2 つ（一覧を読む・1 つ頼む）だけで足りる。操作を足しても道具とその説明は変わらない（natsumi は、ツールの説明を動かさないことで prefix cache を保つ）。
- 引数から値を引く問い合わせの型で書けない対象が出たときだけ、関所のコードを変える。

### git の push

- push は、`git-receive-pack` の命令の並びを読み、ref ごとに操作に揃えて表で決める。対象はリポジトリと ref。
- ref の作成・更新・削除を見分ける。force push かどうかは、関所が上流に問い合わせて見分ける。
- pack の中身は読まない。命令の並びを読めなければ断る。
- 取り込み（fetch・clone）は読みとして通す。

### 最初の表

- 今の中継の許可リストに当たる操作（fork の作成、fork からの PR・issue・コメント・レビュー、自分の fork と自分の private のリポジトリの作成と push）は allow にする。
- PR のマージと tag の作成は ask にする。
  - 運用の係は、マージする PR の一覧（番号・題・head の SHA）を、1 つの承認待ちとして先に頼める（ADR-0004）。
  - マージの許しは 1 回の範囲で、PR ごとに head の SHA に結び付ける。承認の後に head が動けば、許しは当たらない。
  - 会話の中の ok は数えない。
  - tag の承認の画面には、tag を付ける commit と、それが default の branch にあるかを事実として出す。今の中継は default の branch にない commit への tag を断っており、その確かめを本人の判断の材料に移す。
- 今まで床として断っていた種類は deny にする。ref の削除、守っている branch への force push、`/user` 系（自分の private のリポジトリの作成を除く）、Actions の secrets と variables、webhook、deploy key、リポジトリの設定・collaborator・公開範囲。
  - どれも表のデータなので、環境のリポジトリの変更で ask に変えられる（ADR-0004）。
- 上のどれにも当たらない書きは、表に無い操作として ask になる。

### 本当の床は GitHub の側に置く

- machine account は、書き込むリポジトリには write の collaborator として招く。リポジトリの設定・collaborator・公開範囲の変更には admin が要るので、表を誤って緩めてもできない。
- 運用の係の閉じ込めを決めるリポジトリ（natsumi、関所の配置を持つ環境のリポジトリなど）には、書き込みの権限を渡さない。Approve までで、マージは本人がする。
- 守っている branch は、GitHub の ruleset でも守る。

### 守る対象と、倒す向き

- 守るのは、本人がレビューした操作の定義と表に沿った書きだけが GitHub に届くことと、マージと tag が本人の承認なしに通らないことである。
- 許す範囲は、REST と GraphQL の読み、表の allow、台帳の許しに当たる書きである。
- 文書を解けない、命令の並びを読めない、引数から値を引けない、上流への問い合わせに失敗したときは、断る側に倒す。

### 本 ADR で決定しないこと

- 操作の定義の形式（欄の名前、引数の型の書き方、問い合わせの型）（委譲先: 関所の設定の仕様書）。
- 操作の名前の一覧と、REST の method・path から操作への対応（委譲先: 環境のリポジトリの運用の係の設定）。
- 書きを許すリポジトリと、マージを許すリポジトリの一覧（委譲先: 環境のリポジトリの運用の係の設定と、GitHub の collaborator の設定）。
- force push の見分け方と、上流への問い合わせの形（委譲先: 関所の実装の PR）。
- 判定器で GitHub の本文（コメント・PR の本文など）を見ること（委譲先: 判定器を入れる次の版の ADR）。

## Consequences

- GraphQL で読む道具（`gh pr view` など）が使えるようになる。
- GraphQL でしかできない書きも、レビューした定義を足せば操作として許せる。足すのは設定の PR で、関所のリリースは要らない。
- マージと tag は本人の承認で通り、head の SHA に結び付くので、承認の後に積まれた commit は通らない。会話で ok を偽っても通らない。
- 表に無い書きは断られずに聞かれる。最初のうちは聞かれる回数が多い。
- 運用の係の道具は、書きの操作を道具の側で組み立てず、関所に名前と引数で頼む形になる。`gh` の書きのコマンドの多くは、操作の定義が無ければ ask か deny になる。
- 操作の定義が増えると、どの文書が何を書くかのレビューが本人の負担になる。
- 床は GitHub の側の権限と ruleset である。表を誤って緩めれば、machine account の権限の範囲の書きは通る。GitHub の側の権限を広げすぎないことが、床を保つ条件になる。
- GraphQL の読みを通すので、読める範囲は machine account が読める範囲すべてになる。読みは記録に残る（ADR-0006）。

## Alternatives Considered

- **GraphQL を今どおり全部断る**: `gh` の読みが使えず、GraphQL でしかできない書きも許す道が無い。
- **GraphQL の mutation を、文書を解いて中身で判定する**: どの mutation がどの対象に何をするかを、任意の文書から確かめるのは難しい。固定の文書と引数の型に限れば、レビューした範囲だけが通る。
- **運用の係に node ID を渡させる**: node ID は人が読めず、承認の画面で対象を確かめられない。偽った node ID で別の対象を書ける。
- **操作を足すたびに関所のコードを足す**: 操作ごとにリリースが要り、今の「許すたびに PR と apply」より重くなる。
- **マージの ok を会話の中で取り続ける**: 関所が確かめられず、乗っ取られた運用の係が ok を偽れる。会話の ok で済ませたのは、確かめる仕組みが無かったためで、関所が入ればその前提が無くなる。

## Related ADRs

- Related: ADR-0002 作業環境の外向きの通信を透過で関所に通し、宛先ごとに扱いを決める
- Related: ADR-0004 操作の表で決め、表に無いものは本人に聞き、範囲付きの許しを台帳に残す
- Related: ADR-0006 出ていくものを関所の記録に残し、指標と知らせで異常に気づく

## References

- 環境のリポジトリ（private）の運用の係の中継のスクリプト `relay/relay.js` の `githubApiWrite`（REST の書き込みの許可リスト）・`mergeOrTag`・`onDefaultBranch`（マージの許可リスト、tag の commit が default の branch にあるかの確かめ）・`receivePack`（push の命令の並びを読み、ref の削除と守っている branch への push を断る）、冒頭の説明（GraphQL を断る理由）、2026-11-09 確認
- 環境のリポジトリ（private）の運用の係の手引き `tools/README.md`（マージと tag は本人が会話で ok したものだけ）、2026-11-09 確認
- Git「pack-protocol」の `git-receive-pack` の命令の並び（https://git-scm.com/docs/pack-protocol 、2026-11-09 確認）
- GitHub Docs「Forming calls with GraphQL」（query・mutation の operation、https://docs.github.com/en/graphql/guides/forming-calls-with-graphql 、2026-11-09 確認）
