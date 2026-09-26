# 开源漏洞披露协作

这是使用 Python 标准库、SQLite 和 `http.server` 实现的保密漏洞协作后台。系统支持报告人、协调员、维护者三种角色，管理受影响产品版本、私密证明材料、保密期限、修复计划、状态历史、延期、通知和公开公告。

## 启动

```bash
python app.py
```

默认端口 `8113`，页面为 <http://127.0.0.1:8113>。首次启动创建示例网关漏洞。可用环境变量 `PORT` 和 `VULN_DB` 调整端口及数据库位置。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；同时验证外部用户无权查看、相同产品版本会触发重复报告，以及维护者看不到协调员专用材料。公开预览部分覆盖：未指定段落、协调员专用材料、已失效材料会被列为阻断并阻止披露；公开公告只含标题、版本和指定段落，材料仅显示名称与脱敏摘要；报告或草稿改动会使预览失效。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`、`POST /api/evidence/invalidate`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/preview`、`GET /api/reports/{id}/preview?user_id=...`
- `POST /api/reports/{id}/publish`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。

## 公开预览

公告草稿按非空行拆成段落，协调员通过 `POST /api/reports/{id}/preview` 逐段指定 `public_paragraphs`（公开）或 `withheld_paragraphs`（保留），并用 `evidence_ids` 勾选可公开材料。系统把未指定段落、协调员专用材料和已失效材料列为阻断；存在阻断或预览失效时不能披露。材料可由协调员通过 `POST /api/evidence/invalidate` 作废。

报告、公告草稿或材料一旦发生改动，已保存的预览自动失效（状态变为 `stale`），需要协调员重新指定。保密期到达并披露后，`GET /api/reports/{id}/advisory` 对公众只组合标题、受影响版本和指定公开段落，材料仅显示名称与脱敏摘要（邮箱、IP、电话、长编号会被替换为 `[已脱敏]`），不再整段公开协调员草稿。
