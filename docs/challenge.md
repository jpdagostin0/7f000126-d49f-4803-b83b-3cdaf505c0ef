# RWX - Blast Radius

給定一個程式碼變更，挑出能抓到它的測試。跑得越少越好；漏掉一個失敗就要付出代價。

出題：RWX（Dan Manges，RWX 共同創辦人暨 CEO）

## 問題

每個快速的 CI 系統都得決定一個 commit 需要跑哪些測試。全部都跑就要等；跳過錯的那個就會讓 bug 上線。

你會拿到一批對 sqlglot（一個 Python SQL 解析器）的程式碼變更。對每個變更，決定要跑它的哪些測試，以及如何分配到最多 8 個 worker。

大多數變更至少會弄壞一個測試。有些什麼都不會壞，這種情況的正確答案是什麼都不跑。

## 開始

下載下方的 `blast-radius-sample.tar.gz`，解壓到一個空資料夾（壓縮檔沒有最上層資料夾）。需要 Docker、make 和 Python 3.9 以上。

執行 `make sample`：建置起始映像檔，在下列限制下對 30 個範例 commit 執行，並為輸出計分。

## 繳交內容

提交一個最上層有 Dockerfile 的公開 GitHub repo，以及要計分的 commit。任何語言、函式庫與任何程度的 AI 使用皆可。

程式收到的每個變更都是針對 sqlglot commit `eb11aec4be8cb2122afe713a4816662c3f0fb2fa` 的 patch，彼此獨立。

- `/data/commits/<id>.patch`：每個 commit 一份 unified diff。
- `/data/tests.json`：列出所有測試，含編號、檔案路徑與記錄的執行秒數。
- 每個 commit 輸出一行 JSON 到 stdout：`{"commit": "k7q2", "workers": [[12, 845, 901], [3, 77]]}`。每個內層 list 是一個 worker 的測試編號，`"workers": []` 代表什麼都不跑。
- log 送到 stderr。stdout 上有任何其他輸出，或超過 2 MB，整次執行會被拒絕。

## 計分方式

- 一個 commit 的成本 = 最忙 worker 的記錄測試秒數 + 每個 worker 2 秒（最多 8 個 worker）；什麼都不跑成本為 0。
- 若選擇漏掉任何在該 commit 上失敗的測試，加 300 秒。
- 程式的 CPU 秒數會加進總分；決策時跑 sqlglot 的測試是允許的，也會算在這裡。
- 映像檔執行 3 次，取中間的總分，四捨五入到 0.1 秒。

## 「失敗」的定義

當 pytest 回報某測試失敗、錯誤或逾時，或其檔案無法 import 時，該測試就算在該 commit 上失敗。有 subtest 的測試算一個測試，任一 subtest 失敗即算失敗。

只新增註解的變更不保證無害。

## 限制

- repo 最多 20 MB。Git submodule 與 Git LFS 檔案不會被抓取，所以請在 Dockerfile 中 clone sqlglot，並把 map 以一般檔案 commit。
- 建置有網路、4 核、8 GB 記憶體、10 分鐘。建置時可以安裝 sqlglot 並執行其測試來產生 coverage 或 import map。
- 每次提交都從零建置，所以建置時跑 sqlglot 測試的話每次提交都要花好幾分鐘。事先產生一次並 commit 的 map 幾秒就能建置完。
- 執行時沒有網路、2 核、4 GB 記憶體，整批共 3 分鐘（決賽 4.5 分鐘，commit 數約 1.5 倍）。
- 程式以 nobody 使用者執行，`HOME=/tmp`，磁碟唯讀，`/tmp` 是空的 64 MB，最多 256 個 process。

## 文件與起始檔案

- `SCORING.md`：精確的計分規則：輸入檔、stdout 格式、worker 成本、漏抓罰分與 CPU 時間（也在 `blast-radius-sample.tar.gz` 裡）。
- `blast-radius-sample.tar.gz`：起始套件：可用的選擇器、30 個範例 commit 及各自弄壞的測試、本地計分器。

## 計分

| 項目 | 內容 |
| --- | --- |
| 指標 | 模擬 CI 秒數，越低越好 |
| 要超越的基準 | 1614.1 s（Starter：跑全部測試，分到 3 個 worker） |
| 公式 | 最忙 worker 測試秒數 + 每 worker 2 s + 每個漏抓 commit 300 s + CPU 秒數；3 次取中間值 |
| 同分 | 同分時較早提交者排前面。決賽中，與最佳成績相差 1 秒以內者視為同分並以最早者優先，其餘作品從下一個最佳成績開始以同樣方式分組。第一名獲獎。 |
| 計分器版本 | blast-radius-1 |

每個 commit 付出最忙 worker 的記錄測試秒數加每個 worker 2 秒，漏掉任何失敗測試再加 300 秒；程式的 CPU 秒數在整批中累加。分數會附上每次執行的模擬秒數、CPU 秒數與漏抓的 commit 數，但不會告訴你是哪些。

## 規則

- 每個 commit 輸出一行 JSON，最多 8 個 worker，同一 commit 內測試不重複，只能用 `tests.json` 中的測試編號。
- 違反規則、崩潰、逾時、超出記憶體或建置失敗會讓提交被拒絕並附上原因，不會改變你的最佳分數。
- 練習與決賽執行時你永遠看不到程式的輸出。請用 `make sample` 在範例集上本地除錯。
- 一開始每隊每小時可提交一次；佇列一直很短的話會放寬。
- 一人一隊，使用自己隊伍的 repo。隊伍間不得共用程式碼：前段作品會被比對，你可能會被要求解釋。與其他隊伍使用相同 repo、commit 或壓縮檔的提交會被取消資格（較晚的那一方）。
- 建置只能從公開套件庫（PyPI、npm、Docker Hub）、固定 tag 的 GitHub release，以及 commit eb11aec 的 sqlglot 下載。不能從你隊伍控制的位址下載，因為決賽會在截止後重新建置所有映像檔。
- 不得預先算好答案再依 patch 查表：不能有從 patch 或從某類編輯對應到它會弄壞的測試的表。從固定 commit 產生的 map（coverage、import、fixture）是允許的。前段作品會被審閱。
- 在結果公布前，repo 必須保持公開並保留每個提交過的 commit。決賽時無法取得或還原的作品得零分。
- 只有決賽算數。練習榜沒有獎品。
- 若在結果公布前發現標註錯誤的 commit，會為所有隊伍一併修正。

## 決賽

截止時，你選定的 commit（預設為最佳，除非另選）會在未公開的 commit 上計分，其中包含練習中沒有的變更類型。之後至少前 5 名會在同一批 commit 上重新計分，每隊 5 次（而非 3 次），一次一隊，在同一台閒置機器上執行；其中間總分取代第一次的分數。

截止時間：週日上午 11:00 EST。
