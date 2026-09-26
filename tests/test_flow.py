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
    def _advance_to_resolved(self, draft="受影响版本 3.2.0。请升级到 3.2.1。"):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.set_status(self.report,"triaged",self.coord)
        self.db.set_status(self.report,"fixing",self.coord)
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验", "2026-10-20")
        self.db.set_status(self.report,"resolved",self.coord)
        self.db.create_advisory_draft(self.report,draft,self.coord)
    def _clean_preview(self, public=(0,), withheld=(), evidence_ids=()):
        return self.db.save_public_preview(self.report,self.coord,list(public),list(withheld),list(evidence_ids))
    def test_full_disclosure_flow_and_early_publish_rejected(self):
        self._advance_to_resolved()
        self._clean_preview()
        with self.assertRaisesRegex(DomainError,"提前披露"):
            self.db.publish_report(self.report,self.coord,"2026-10-01")
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        advisory=self.db.get_advisory(self.report,self.outsider)
        self.assertEqual("published",advisory["status"])
        self.assertEqual(["受影响版本 3.2.0。请升级到 3.2.1。"],advisory["paragraphs"])
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
    def test_preview_blockers_gate_publish(self):
        self._advance_to_resolved("公开说明：请升级到 3.2.1。\n内部联系人：sec@example.com。\n保留段落。")
        secret=self.db.add_evidence(self.report,"协调笔记","内部电话 13800001111","coordinator",self.coord)
        stale=self.db.add_evidence(self.report,"过期日志","旧日志内容","private",self.reporter)
        self.db.invalidate_evidence(stale,self.coord)
        view=self._clean_preview(public=(0,), withheld=(), evidence_ids=(secret,stale))
        self.assertFalse(view["ready"])
        blob="；".join(view["blockers"])
        self.assertIn("未指定",blob); self.assertIn("协调员专用",blob); self.assertIn("已失效",blob)
        with self.assertRaisesRegex(DomainError,"阻断"):
            self.db.publish_report(self.report,self.coord,"2026-10-30")
        view=self._clean_preview(public=(0,), withheld=(1,2), evidence_ids=())
        self.assertTrue(view["ready"])
        self.db.publish_report(self.report,self.coord,"2026-10-30")
    def test_public_advisory_only_contains_designated_content(self):
        self._advance_to_resolved("受影响版本 3.2.0，请尽快升级。\n内部联系人：sec@example.com 请勿外传。")
        evidence=self.db.add_evidence(self.report,"复现日志","复现步骤联系 admin@example.com 获取，IP 10.0.0.8","private",self.reporter)
        self._clean_preview(public=(0,), withheld=(1,), evidence_ids=(evidence,))
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        advisory=self.db.get_advisory(self.report,self.outsider)
        text=json.dumps(advisory,ensure_ascii=False)
        self.assertIn("受影响版本 3.2.0",text)
        self.assertNotIn("内部联系人",text)
        self.assertNotIn("sec@example.com",text)
        self.assertNotIn("admin@example.com",text)
        self.assertEqual("复现日志",advisory["materials"][0]["name"])
        self.assertIn("[已脱敏]",advisory["materials"][0]["summary"])
        self.assertEqual("3.2.0",advisory["versions"][0]["version_key"])
    def test_preview_invalidated_by_report_or_draft_changes(self):
        self._advance_to_resolved()
        self._clean_preview()
        self.db.create_advisory_draft(self.report,"公告内容已重写，需要重新指定公开段落。",self.coord)
        view=self.db.get_public_preview(self.report,self.coord)
        self.assertEqual("stale",view["preview"]["status"])
        self.assertFalse(view["ready"])
        with self.assertRaisesRegex(DomainError,"失效"):
            self.db.publish_report(self.report,self.coord,"2026-10-30")
        self._clean_preview()
        self.db.add_evidence(self.report,"补充截图","截图内容","private",self.reporter)
        view=self.db.get_public_preview(self.report,self.coord)
        self.assertEqual("stale",view["preview"]["status"])
    def test_only_coordinator_manages_preview_and_materials(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"协调员"):
            self.db.save_public_preview(self.report,self.maint,[0])
        evidence=self.db.add_evidence(self.report,"复现日志","内容","private",self.reporter)
        with self.assertRaisesRegex(DomainError,"协调员"):
            self.db.invalidate_evidence(evidence,self.maint)
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.get_public_preview(self.report,self.outsider)

if __name__=="__main__": unittest.main()
