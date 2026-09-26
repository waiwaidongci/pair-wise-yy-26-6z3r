import json, os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import DomainError, VulnerabilityDB

class VulnerabilityFlowTest(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix=".db"); os.close(fd); self.db=VulnerabilityDB(self.path)
        self.reporter=self.db.add_user("报告人","reporter","研究所"); self.coord=self.db.add_user("协调员","coordinator","响应中心"); self.maint=self.db.add_user("维护者","maintainer","项目组"); self.outsider=self.db.add_user("旁观者","reporter","外部")
        self.product=self.db.add_product("网关","项目组")
        self.report=self.db.create_report("鉴权绕过",self.product,self.reporter,"特制请求可绕过鉴权","2026-10-30",["3.2.0"])
    def tearDown(self): self.db.close(); os.unlink(self.path)
    def _advance_to_resolved(self):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.set_status(self.report,"triaged",self.coord)
        self.db.set_status(self.report,"fixing",self.coord)
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验", "2026-10-20")
        self.db.set_status(self.report,"resolved",self.coord)
        self.db.create_advisory_draft(self.report,"受影响版本 3.2.0。请升级到 3.2.1。",self.coord)
    def test_full_disclosure_flow_and_early_publish_rejected(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"提前披露"):
            self.db.publish_report(self.report,self.coord,"2026-10-01")
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        advisory=self.db.get_advisory(self.report,self.outsider)
        self.assertEqual("published",advisory["status"])
        self.assertTrue(self.db.notifications_for(self.maint))
    def test_denies_outsider_and_duplicate_report(self):
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.get_report_for_user(self.report,self.outsider)
        with self.assertRaisesRegex(DomainError,"重复"):
            self.db.create_report("重复问题",self.product,self.reporter,"相同版本的另一份报告","2026-11-01",["3.2.0"])
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.add_evidence(self.report,"协调材料","secret","coordinator",self.coord)
        visible=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],visible["evidence"])
    def _advance_to_preview(self):
        self._advance_to_resolved()
        self.db.create_advisory_draft(self.report,"受影响版本 3.2.0，请尽快升级。\n\n内部联系人 sec@example.com 电话 13800001111。\n\n升级后重启网关即可生效。",self.coord)
        self.public_ev=self.db.add_evidence(self.report,"复现脚本","GET /admin HTTP/1.1 联系 ops@example.com","private",self.reporter)
        self.coord_ev=self.db.add_evidence(self.report,"协调记录","内部协调电话 13900002222","coordinator",self.coord)
        self.stale_ev=self.db.add_evidence(self.report,"过期截图","旧版本截图，已不适用","private",self.reporter)
        self.db.invalidate_evidence(self.stale_ev,self.coord)
    def test_public_preview_lists_blockers(self):
        self._advance_to_preview()
        preview=self.db.create_public_preview(self.report,self.coord,[0,2],[self.public_ev])
        self.assertTrue(preview["valid"])
        self.assertEqual(["受影响版本 3.2.0，请尽快升级。","升级后重启网关即可生效。"],preview["paragraphs"])
        self.assertEqual([1],[b["index"] for b in preview["blockers"]["paragraphs"]])
        self.assertEqual(["协调记录"],[b["name"] for b in preview["blockers"]["coordinator_evidence"]])
        self.assertEqual(["过期截图"],[b["name"] for b in preview["blockers"]["invalidated_evidence"]])
        self.assertEqual("复现脚本",preview["materials"][0]["name"])
        self.assertNotIn("ops@example.com",preview["materials"][0]["summary"])
        with self.assertRaisesRegex(DomainError,"协调员专用材料"):
            self.db.create_public_preview(self.report,self.coord,[0],[self.coord_ev])
        with self.assertRaisesRegex(DomainError,"已失效材料"):
            self.db.create_public_preview(self.report,self.coord,[0],[self.stale_ev])
        with self.assertRaisesRegex(DomainError,"协调员"):
            self.db.create_public_preview(self.report,self.maint,[0],[])
        with self.assertRaisesRegex(DomainError,"协调员"):
            self.db.invalidate_evidence(self.public_ev,self.maint)
    def test_public_page_uses_only_designated_content(self):
        self._advance_to_preview()
        self.db.create_public_preview(self.report,self.coord,[0,2],[self.public_ev])
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        public=self.db.get_advisory(self.report,self.outsider)
        self.assertEqual("published",public["status"])
        self.assertTrue(public["preview_valid"])
        self.assertEqual("受影响版本 3.2.0，请尽快升级。\n\n升级后重启网关即可生效。",public["content"])
        self.assertNotIn("sec@example.com",json.dumps(public,ensure_ascii=False))
        self.assertNotIn("summary",public)
        self.assertEqual([{"version_key":"3.2.0","details":""}],public["versions"])
        self.assertEqual("复现脚本",public["materials"][0]["name"])
        self.assertNotIn("ops@example.com",public["materials"][0]["summary"])
        internal=self.db.get_advisory(self.report,self.coord)
        self.assertIn("内部联系人",internal["content"])
        self.assertEqual(public["content"],internal["public"]["content"])
    def test_preview_invalidated_by_report_or_draft_changes(self):
        self._advance_to_preview()
        self.db.create_public_preview(self.report,self.coord,[0,2],[self.public_ev])
        self.db.create_advisory_draft(self.report,"改写后的草稿，只有一段但足够长。",self.coord)
        self.assertFalse(self.db.get_public_preview(self.report,self.coord)["valid"])
        self.db.create_public_preview(self.report,self.coord,[0],[])
        self.assertTrue(self.db.get_public_preview(self.report,self.coord)["valid"])
        self.db.extend_embargo(self.report,"2026-11-15","需要更多时间验证修复",self.coord)
        self.assertFalse(self.db.get_public_preview(self.report,self.coord)["valid"])
        self.db.create_public_preview(self.report,self.coord,[0],[])
        self.db.add_evidence(self.report,"补充材料","新的复现步骤","private",self.reporter)
        self.assertFalse(self.db.get_public_preview(self.report,self.coord)["valid"])
    def test_stale_preview_not_used_on_public_page(self):
        self._advance_to_preview()
        self.db.create_public_preview(self.report,self.coord,[0,2],[self.public_ev])
        self.db.create_advisory_draft(self.report,"改动后的草稿内容，包含新的公开说明。",self.coord)
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        public=self.db.get_advisory(self.report,self.outsider)
        self.assertFalse(public["preview_valid"])
        self.assertEqual("",public["content"])
        self.assertEqual([],public["paragraphs"])
        self.assertEqual([],public["materials"])

if __name__=="__main__": unittest.main()
