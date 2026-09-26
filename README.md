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

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；同时验证外部用户无权查看、相同产品版本会触发重复报告，维护者看不到协调员专用材料，以及公开预览的阻断清单、公开页只含指定段落与脱敏材料、报告或草稿改动使预览失效。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/preview`、`GET /api/reports/{id}/preview?user_id=...`
- `POST /api/evidence/{id}/invalidate`
- `POST /api/reports/{id}/publish`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。

## 公开预览

公告不再整段公开。协调员用 `POST /api/reports/{id}/preview` 指定可公开段落（草稿按空行分段，序号从 0 开始）并勾选可公开材料；预览响应把未指定段落、协调员专用材料和已失效材料列为阻断项，勾选协调员专用或已失效材料会直接失败。`POST /api/evidence/{id}/invalidate` 由协调员作废材料。保密期到达并披露后，公开公告只组合标题、受影响版本和指定段落，材料仅显示名称与脱敏摘要（邮箱、长串数字打码并截断）。报告内容、材料或公告草稿改动会使预览指纹失效，公开页随即停用原预览，需协调员重新生成。
