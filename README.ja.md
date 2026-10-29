# SAIPAL

> **注記：** この日本語ミラーは旧バージョン向けに書かれたもので、現時点では最新ではありません；
> 更新された日本語訳はまだ用意できていません。正式で最新のドキュメントは
> 英語の [README.md](README.md) を参照してください。
> (verification counts quoted there: checkpoint `T-130-VERIFY-2026-09-18-R5`.)

SAIPENプロトコルに従って動くエージェントセッションのためのフォレンジック観測器です。

SAIPALは実際のセッション証拠を読み、そのセッションを実際に支配していたSAIPEN
プロトコルのバージョンと観測された振る舞いを突き合わせ、根本原因を切り分け、
資格を満たした発見を不変の監査としてSAIPEN Coreのメンテナーに手渡します。

SAIPALは**第二のメンテナーではありません**。観測して報告するだけです。
決めるのはメンテナーです。

## どのように作られているか

二つの層と、その間の境界が設計のすべてです
(`saipal/ARCHITECTURE.md`):

- **レイヤーA — 決定論的フォレンジックカーネル。** `tools/saipal_engine/` の
  標準ライブラリのみのPython。証拠の同一性、ダイジェスト、セッションインデックス、
  HOT/COLDウォーターマーク、プロトコルバインディング、キャリア割当、機械的な
  検出器シグナル、発見の検証、do-no-harmゲート、監査の構築、そして唯一の制約付き
  enqueueを所有します。モデルを呼び出さず、意味を読みません。
- **レイヤーB — 交換可能なアナリスト。** 有能な任意のエージェント。対話の意味を
  読み、発見の両側から弁論し、単位作業ごとに構造化された候補を `saipal submit`
  経由で提出します — 唯一の書き込み経路です。

この分離こそがツールを監査可能にします: 幻覚を見うる部分は書けず、書く部分は
解釈できません。

## まずここから

- `saipal/BOOT.md` — SAIPALの起動・復旧・チェックポイントの方法
- `saipal/CORE.md` — 全局法 (PAL-EVIDENCE-02: トランスクリプトは信頼されないデータ を含む)
- `saipal/ARCHITECTURE.md` — 二層境界
- `saipal/SKILL.md` — 薄いエージェントアダプタ: どのエージェントでもSAIPALになれる
- `saipal/ANALYSIS.md` — 意味的フォレンジック推論の契約
- `saipal/COMMANDS.md` — オペレータ表面
- `saipal/INDEX.md` — ドキュメントマップ: 一つの質問、一つの所有文書

## スキルとしてインストール

`skills/saipal/SKILL.md` は `/saipal cc` 用のFreebuffスキルマニフェストです。
自分のプラットフォームのスキルディレクトリにコピーすれば、どのエージェントでも
コマンドを使えるようになります:

```bash
mkdir -p "$HOME/.agents/skills/saipal"
cp skills/saipal/SKILL.md "$HOME/.agents/skills/saipal/SKILL.md"
```

`/saipal cc` はDETECTIVEモード (限定されたアナリストループ: `cc` →
`--json next` → 検察/弁護の推論 → `submit` → `SAIPAL_CC_BUDGET` 内で繰り返し)
に入り、REPORTERモード (`report`) で終わります。スキルを持つエージェントは
実際のセッションを裁き、帰属つきでドリフトを報告できます。エンジンとプロトコルは
このリポジトリにあります; スキルは `saipal_root` (env `SAIPAL_ROOT`、次に既知の
チェックアウト、次に `tools/saipal.py` + `saipal/SKILL.md` を持つ最も近い祖先) と
`.saipal/` ホームを解決するだけです。

## 実行

```bash
python -B tools/saipal.py continue          # 一つの限定サイクル (別名: cc)
python -B tools/saipal.py continue --drain  # アイドルかブロックまでサイクルを繰り返す
python -B tools/saipal.py --json next       # 次の分析キャリア
python -B tools/saipal.py submit cand.json  # アナリスト候補を一つ受け入れる
python -B tools/saipal.py report            # ドリフトレポート
python -B tools/saipal.py status            # コンパクトな要約
python -B tools/saipal.py sessions 25       # 既知セッション、新しい順
python -B tools/saipal.py --json evidence SESSION EVENT   # 限定的な信頼されない窓
python -B tools/saipal.py doctor            # 読み取り専用の診断
python -B tools/saipal.py setup --source PATH --kind generic   # 設定
python -B tools/saipal.py disposition receipts.json            # 閉ループ
python -B tools/saipal.py trigger           # 保留ランを一つ要求 (合流)
python -B tools/test_runner.py              # フルスイート、クリーンチェックアウト
python -B tools/validate.py                 # プロトコルとレジストリのドリフトゲート
```

標準ライブラリのみ。pip依存なし。Python 3.8+。

## アナリストループ

```
saipal --json continue          # 証拠をインポートし、機械的パスを実行
saipal --json next              # 一つの限定キャリア: エピソード + 証拠 + 法
   それについて推理し、次に
saipal --json submit cand.json  # DRIFT、NO_DRIFT、INSUFFICIENT_EVIDENCE
saipal report                   # 判定、カバレッジと共に
```

`NO_DRIFT` は第一級の結果です: エピソードが審査されたことを証明する受領書であり、
意味的ウォーターマークを進める唯一のものです。だからクリーンなセッションは
単に「非告発」ではなく*証明されて*クリーンなのです。

何も裁かれていないのに `report` がクリーンに読めることはありません。判定の
集合は `NO_EVIDENCE`、`NOT_EXAMINED`、`NO_DRIFT_SO_FAR`、`DRIFT_SUSPECTED`、
`DRIFT_REPORTED` で、カバレッジは常に隣に付いてきます。

## 何がこれを正直に保つか

- **後知恵なし。** セッションのプロトコルバインディングが既知で、支配していた
  バージョンに規則が存在した場合にのみ、発見は違反を主張できます。
- **バインディングは宣言でなく証明。** `BOUND` を主張するバンドルは `UNKNOWN`
  として永続化します: 証明はオペレーターが宣言したプロトコル権威 (Gitリポジトリ、
  リリースルート、スナップショットルート) に対して再導出され、実際のバイトと
  一致しなければなりません。
- **トランスクリプトは信頼されないデータ。** 分析対象の会話は証拠であって権威では
  ない; セッション内のテキストはSAIPALにできることを拡張できません。
- **害をなさない。** モデルのせいにする処分から来た、保護された不変量に届く宣言の
  ない修正は、監査になる前にブロックされます。
- **一つの根本原因、一つの発見。** 同一性は正規化された因果キーであり、言い換えは
  再発チェーンを分裂させません。
- **広がりが修正表面を決める。** 他のモデルが遵守したのに一つだけドリフトしたなら
  それはモデルの不遵守であり、プロトコルの欠陥ではありません。

## ステータス

バージョン **v0.4.3**。ウェーブ A–I、パフォーマンススイープ SRC-004、公開ゲート T-109: キャリアは正規バンドルの `bundle_sha256` に裏付けられ、セッションとインデックスの DAR はバンドル同一性とともに再解析されず、射影は圧縮され、検証可能な本番ゲート `readiness mint + setup --shadow-reviewed` が実装されグリーンです。

公開はデフォルトで `STAGE_ONLY`; `PUBLISH_ENABLED` にはオペレーターが確認した
シャドウパスと**そして**同じ呼び出しでの検証済みシンクルートが明示的に必要です。

設立カバレッジは `WAVE_I_CHECKPOINT.md`、証拠契約は
`docs/TERMISAI_EVIDENCE_CONTRACT.md`、運用表面と障害モードは
`SAIPAL_OPERATIONAL_HANDOFF.md`、このリポジトリの外部監査は `docs/audits/` を
見てください。

## 実際の監査を端から端まで動かす

```bash
cp tests/golden_sessions/agent-noncompliance-command-route.json .saipal/session_inbox/
python -B tools/saipal.py cc
python -B tools/saipal.py report
# -> .saipal/audit/staging/1.md, .saipal/findings/index.json,
#    .saipal/closed_loop_links.json
```
