"""HR onboarding HTTP demo scenario."""

from __future__ import annotations

from scenarios.common import DemoCall, DemoScenario


def scenario() -> DemoScenario:
    return DemoScenario(
        agent_id="hr_onboarding_bot",
        display_name="HR Onboarding Bot",
        architecture="HTTP",
        agent_owner="Elena Brooks, People Ops",
        llm_provider="openai/gpt-5.2",
        handles=("personal_info",),
        allowed_tools=(
            "create_employee_profile",
            "provision_payroll",
            "send_welcome_packet",
        ),
        blocked_tools=("email_tax_form_pdf",),
        calls=(
            DemoCall(
                tool_name="create_employee_profile",
                arguments={
                    "employee": "Robin Lee",
                    "email": "robin.lee@example.com",
                    "phone": "212-555-0172",
                    "destination": "hris.internal",
                },
                response="Employee profile EMP-2026-044 created.",
                detected_data_types=("DC-PII",),
                description="Create an employee profile in the HRIS.",
            ),
            DemoCall(
                tool_name="provision_payroll",
                arguments={
                    "employee_id": "EMP-2026-044",
                    "bank_last4": "0442",
                    "tax_region": "NY",
                    "destination": "payroll.internal",
                },
                response="Payroll setup queued for controller approval.",
                outcome="FLAG",
                detected_data_types=("DC-PII",),
                reason="Flagged because payroll onboarding requires reviewer confirmation.",
                description="Send PII to payroll for onboarding.",
            ),
            DemoCall(
                tool_name="send_welcome_packet",
                arguments={
                    "employee_id": "EMP-2026-044",
                    "email": "robin.lee@example.com",
                    "template": "remote-employee-day-one",
                    "destination": "notifications.internal",
                },
                response="Welcome packet sent.",
                detected_data_types=("DC-PII",),
                description="Send first-day onboarding instructions.",
            ),
            DemoCall(
                tool_name="email_tax_form_pdf",
                arguments={
                    "employee_id": "EMP-2026-044",
                    "ssn": "123-45-6789",
                    "destination": "plain-email",
                },
                response="Blocked before tax form PDF was emailed.",
                outcome="BLOCK",
                detected_data_types=("DC-PII",),
                reason="Blocked because SSN-bearing forms cannot be sent over plain email.",
                description="Unsafe attempt to email a tax form with SSN.",
            ),
        ),
    )
