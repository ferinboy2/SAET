"""
Catalog ของ MITRE ATT&CK Technique ที่พบบ่อยใน SOC operations
Technique ID / ชื่อ / tactic อ้างอิงจาก MITRE ATT&CK (public framework)
คำแนะนำ Prevent/Detect/Respond เขียนขึ้นเองตาม best practice ทั่วไป ไม่ใช่คัดลอกจากแหล่งใด

ขยาย catalog นี้ได้ตามต้องการ — ถ้าจะโหลดจาก MITRE ATT&CK STIX bundle ทั้งชุดในอนาคต
ให้เขียน loader แยกต่างหากที่ produce ออกมาเป็น dict[str, AttackTechnique] แบบเดียวกันนี้
แล้วสลับใน StaticAttackMapper ได้โดยไม่กระทบ use case
"""
from domain.entities.attack_technique import AttackTechnique

TECHNIQUE_CATALOG: dict[str, AttackTechnique] = {
    "T1566": AttackTechnique(
        technique_id="T1566",
        name="Phishing",
        tactic="Initial Access",
        prevent_guidance=[
            "ใช้ email security gateway กรอง attachment/link อันตราย",
            "บังคับ MFA ทุก account ที่เข้าถึงระบบสำคัญ",
            "ทำ security awareness training เรื่อง phishing สม่ำเสมอ",
        ],
        detect_guidance=[
            "ตรวจ log การเปิด attachment/คลิกลิงก์ต้องสงสัยจาก proxy/EDR",
            "ตั้ง alert เมื่อมี inbox rule แปลกๆ ถูกสร้างหลังพนักงานเปิดอีเมล",
        ],
        respond_guidance=[
            "reset password และ revoke session ของ account ที่โดน",
            "quarantine อีเมลลักษณะเดียวกันทั้งองค์กรทันที",
        ],
    ),
    "T1566.002": AttackTechnique(
        technique_id="T1566.002",
        name="Phishing: Spearphishing Link",
        tactic="Initial Access",
        prevent_guidance=[
            "ใช้ URL rewriting/sandboxing ตรวจลิงก์ก่อนถึงผู้ใช้",
            "จำกัดสิทธิ์ browser extension และ auto-download",
        ],
        detect_guidance=[
            "ตรวจ DNS/proxy log หา domain ที่เพิ่งจดทะเบียนใหม่ (newly registered domain)",
            "ตรวจสอบการ redirect ไปหน้า login ปลอมที่คล้าย brand องค์กร",
        ],
        respond_guidance=[
            "block domain/URL ที่เกี่ยวข้องที่ perimeter ทันที",
            "แจ้งเตือนพนักงานที่อาจได้รับอีเมลเดียวกัน",
        ],
    ),
    "T1078": AttackTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        prevent_guidance=[
            "บังคับ MFA และ conditional access ตาม risk-based",
            "ทบทวนสิทธิ์ privileged account เป็นระยะ (access review)",
        ],
        detect_guidance=[
            "ตั้ง alert การ login จาก location/เวลาผิดปกติ (impossible travel)",
            "ตรวจ log การใช้ account เดียวกัน login พร้อมกันหลายที่",
        ],
        respond_guidance=[
            "disable account ทันทีที่สงสัยว่าถูก compromise",
            "บังคับ reset credential ทุกระบบที่ account นั้นเข้าถึงได้",
        ],
    ),
    "T1486": AttackTechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        prevent_guidance=[
            "ทำ backup แบบ 3-2-1 และเก็บสำเนา offline/immutable",
            "จำกัดสิทธิ์เขียนไฟล์ share/network drive เท่าที่จำเป็น",
        ],
        detect_guidance=[
            "ตั้ง alert เมื่อมีการเปลี่ยนนามสกุลไฟล์จำนวนมากในเวลาสั้นๆ",
            "ตรวจ process ที่เข้าถึงไฟล์จำนวนมากผิดปกติ (mass file I/O)",
        ],
        respond_guidance=[
            "ตัดเครือข่าย (isolate) เครื่องที่ติดทันทีเพื่อจำกัดการแพร่กระจาย",
            "กู้คืนจาก backup ที่ยืนยันว่าสะอาด ก่อน restore เข้าระบบ production",
        ],
    ),
    "T1490": AttackTechnique(
        technique_id="T1490",
        name="Inhibit System Recovery",
        tactic="Impact",
        prevent_guidance=[
            "จำกัดสิทธิ์การลบ shadow copy/backup ให้เฉพาะ admin ที่จำเป็น",
        ],
        detect_guidance=[
            "ตั้ง alert เมื่อมีคำสั่งลบ shadow copy (เช่น vssadmin delete shadows)",
        ],
        respond_guidance=[
            "ตรวจสอบว่ามี backup แยกที่ไม่ถูกลบเหลืออยู่หรือไม่ก่อนตัดสินใจขั้นตอนถัดไป",
        ],
    ),
    "T1059": AttackTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        prevent_guidance=[
            "จำกัดการใช้ PowerShell/script ด้วย application control (allowlisting)",
            "เปิด PowerShell logging/Script Block Logging",
        ],
        detect_guidance=[
            "ตรวจ log คำสั่ง script ที่ encode/obfuscate ผิดปกติ",
        ],
        respond_guidance=[
            "ระงับ process script ที่ต้องสงสัยและเก็บ memory dump เพื่อวิเคราะห์",
        ],
    ),
    "T1053": AttackTechnique(
        technique_id="T1053",
        name="Scheduled Task/Job",
        tactic="Persistence / Privilege Escalation / Execution",
        prevent_guidance=[
            "จำกัดสิทธิ์การสร้าง scheduled task ให้เฉพาะ admin",
        ],
        detect_guidance=[
            "ตั้ง alert เมื่อมีการสร้าง/แก้ scheduled task ใหม่บน critical server",
        ],
        respond_guidance=[
            "ลบ task ที่ผิดปกติและตรวจสอบว่ามี persistence mechanism อื่นแฝงอยู่หรือไม่",
        ],
    ),
    "T1055": AttackTechnique(
        technique_id="T1055",
        name="Process Injection",
        tactic="Defense Evasion / Privilege Escalation",
        prevent_guidance=[
            "เปิดใช้ endpoint protection ที่ตรวจจับ code injection (EDR)",
        ],
        detect_guidance=[
            "ตรวจ process ที่มี memory region แปลกปลอมหรือ parent-child ผิดปกติ",
        ],
        respond_guidance=[
            "kill process ที่ต้องสงสัยและตรวจ endpoint ทั้งเครื่องหา indicator เพิ่มเติม",
        ],
    ),
    "T1071": AttackTechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        prevent_guidance=[
            "ใช้ egress filtering/firewall จำกัด traffic ขาออกเท่าที่จำเป็น",
        ],
        detect_guidance=[
            "ตรวจ traffic pattern ที่ beacon เป็นช่วงเวลาสม่ำเสมอ (periodic beaconing)",
        ],
        respond_guidance=[
            "block C2 domain/IP ที่ perimeter และตรวจเครื่องที่สื่อสารด้วยทั้งหมด",
        ],
    ),
    "T1105": AttackTechnique(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
        prevent_guidance=[
            "จำกัดสิทธิ์ download/execute ไฟล์จากอินเทอร์เน็ตบนเครื่อง critical",
        ],
        detect_guidance=[
            "ตรวจ log การดาวน์โหลดไฟล์ executable จาก IP/domain ที่ไม่รู้จัก",
        ],
        respond_guidance=[
            "ลบไฟล์ที่ถูกดาวน์โหลดและตรวจสอบ hash กับ threat intel",
        ],
    ),
    "T1190": AttackTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        prevent_guidance=[
            "patch ระบบที่เปิดสู่อินเทอร์เน็ตให้ทันเวลา (patch management)",
            "ใช้ WAF ป้องกัน exploit ที่รู้จัก",
        ],
        detect_guidance=[
            "ตรวจ WAF/IDS log หา payload การ exploit ที่ผิดปกติ",
        ],
        respond_guidance=[
            "isolate ระบบที่ถูก exploit และ patch ช่องโหว่ก่อนนำกลับเข้าระบบ",
        ],
    ),
    "T1003": AttackTechnique(
        technique_id="T1003",
        name="OS Credential Dumping",
        tactic="Credential Access",
        prevent_guidance=[
            "เปิด Credential Guard/LSA protection บน Windows",
            "จำกัดสิทธิ์ local admin เท่าที่จำเป็น",
        ],
        detect_guidance=[
            "ตั้ง alert เมื่อมี process เข้าถึง LSASS memory ผิดปกติ",
        ],
        respond_guidance=[
            "reset credential ทั้งหมดที่อาจถูก dump และตรวจการใช้งานย้อนหลัง",
        ],
    ),
    "T1021": AttackTechnique(
        technique_id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        prevent_guidance=[
            "จำกัด RDP/SMB/SSH ให้เข้าถึงได้เฉพาะผ่าน jump host/VPN",
        ],
        detect_guidance=[
            "ตรวจ log การเชื่อมต่อ remote service ข้าม segment ที่ไม่เคยเกิดขึ้นมาก่อน",
        ],
        respond_guidance=[
            "ตัดการเชื่อมต่อและ segment เครื่องที่เกี่ยวข้องออกจากเครือข่ายหลัก",
        ],
    ),
}


def lookup_technique(ttp_id: str) -> AttackTechnique | None:
    """
    หา technique ตรงตัวก่อน ถ้าไม่เจอ (เช่น sub-technique ที่ยังไม่มีใน catalog)
    ให้ fallback ไปหา parent technique (ตัดส่วนหลังจุดออก)
    """
    if ttp_id in TECHNIQUE_CATALOG:
        return TECHNIQUE_CATALOG[ttp_id]
    if "." in ttp_id:
        parent_id = ttp_id.split(".", 1)[0]
        return TECHNIQUE_CATALOG.get(parent_id)
    return None
