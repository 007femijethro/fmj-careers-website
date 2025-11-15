import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from dotenv import load_dotenv
from sqlalchemy import create_engine, text


# -------------------------------------------------------------
# Environment / Engine
# -------------------------------------------------------------
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
if not SUPABASE_URL:
    raise RuntimeError("SUPABASE_URL is not set in environment variables")

# Supabase → Postgres connection string
engine = create_engine(SUPABASE_URL, connect_args={"sslmode": "require"})


# -------------------------------------------------------------
# Jobs
# -------------------------------------------------------------
def get_jobs() -> List[Dict[str, Any]]:
    """Fetch all jobs from fmjjobs table."""
    with engine.connect() as conn:
        result = conn.execute(text('SELECT * FROM "fmjjobs"'))
        return [dict(row) for row in result.mappings()]


def get_job(id: int) -> Optional[Dict[str, Any]]:
    """Fetch a specific job by ID from fmjjobs."""
    with engine.connect() as conn:
        result = conn.execute(
            text('SELECT * FROM "fmjjobs" WHERE id = :val'),
            {"val": id},
        )
        row = result.mappings().first()
        return dict(row) if row else None


# -------------------------------------------------------------
# Applications
# -------------------------------------------------------------
def add_application_to_db(job_title, data):
    """
    Insert job application into the database.

    Expected table (add the new location columns if they don't exist yet):

        CREATE TABLE applications (
            id BIGSERIAL PRIMARY KEY,
            job_title TEXT,
            full_name TEXT,
            email TEXT,
            country_code TEXT,
            phone_number TEXT,
            city TEXT,
            state TEXT,
            country TEXT,
            linkedin_url TEXT,
            education TEXT,
            work_experience TEXT,
            resume_url TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
    """
    from sqlalchemy import text as _text

    with engine.begin() as conn:
        query = _text(
            """
            INSERT INTO applications (
                job_title,
                full_name,
                email,
                country_code,
                phone_number,
                city,
                state,
                country,
                linkedin_url,
                education,
                work_experience,
                resume_url
            )
            VALUES (
                :job_title,
                :full_name,
                :email,
                :country_code,
                :phone_number,
                :city,
                :state,
                :country,
                :linkedin_url,
                :education,
                :work_experience,
                :resume_url
            )
            """
        )
        conn.execute(
            query,
            {
                "job_title": job_title,
                "full_name": data.get("full_name"),
                "email": data.get("email"),
                "country_code": data.get("country_code"),
                "phone_number": data.get("phone_number"),
                "city": data.get("city"),
                "state": data.get("state"),
                "country": data.get("country"),
                "linkedin_url": data.get("linkedin_url"),
                "education": data.get("education"),
                "work_experience": data.get("work_experience"),
                "resume_url": data.get("resume_path"),
            },
        )


def set_application_status(
    application_id: int,
    status: str,
    interview_time: Optional[str] = None,
) -> None:
    """
    Set a manual pipeline status and (optionally) an interview_time note.

    The first 3 statuses (Applied, Email Sent, Interview Scheduled)
    are normally automatic. This helper lets you override with:
      - Interviewing
      - Interview Passed
      - Agreed to Proceed
      - Check Sent
      - Money Dropped
      - Cashed out
      - Equipment Sent
    """
    with engine.connect() as conn:
        conn.execute(
            text(
                """
                INSERT INTO application_tracking (
                  application_id,
                  pipeline_status,
                  interview_time,
                  created_at,
                  updated_at
                )
                VALUES (
                  :application_id,
                  :status,
                  :interview_time,
                  NOW(),
                  NOW()
                )
                ON CONFLICT (application_id) DO UPDATE
                SET pipeline_status = EXCLUDED.pipeline_status,
                    interview_time = COALESCE(EXCLUDED.interview_time, application_tracking.interview_time),
                    updated_at = NOW();
                """
            ),
            {
                "application_id": application_id,
                "status": status,
                "interview_time": interview_time,
            },
        )


def get_application_by_id(application_id: int) -> Optional[Dict[str, Any]]:
    """Fetch a single application row by its id."""
    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT * FROM applications WHERE id = :id"),
            {"id": application_id},
        )
        row = result.mappings().first()
        return dict(row) if row else None


# -------------------------------------------------------------
# Interview scheduling emails (scheduled_interview_emails)
# -------------------------------------------------------------
def schedule_interview_email(job_title: str, data: Dict[str, Any], scheduled_at: datetime) -> None:
    """
    Store a scheduled interview email in the DB.

    Expects table:

        CREATE TABLE scheduled_interview_emails (
          id BIGSERIAL PRIMARY KEY,
          job_title TEXT NOT NULL,
          full_name TEXT NOT NULL,
          email TEXT NOT NULL,
          scheduled_at TIMESTAMPTZ NOT NULL,
          sent BOOLEAN NOT NULL DEFAULT FALSE,
          sent_at TIMESTAMPTZ
        );
    """
    full_name = data.get("full_name")
    email = data.get("email")

    if not full_name or not email:
        raise ValueError("schedule_interview_email requires full_name and email")

    with engine.connect() as conn:
        query = text(
            """
            INSERT INTO scheduled_interview_emails (
                job_title,
                full_name,
                email,
                scheduled_at,
                sent
            ) VALUES (
                :job_title,
                :full_name,
                :email,
                :scheduled_at,
                FALSE
            )
            """
        )
        conn.execute(
            query,
            {
                "job_title": job_title,
                "full_name": full_name,
                "email": email,
                "scheduled_at": scheduled_at,
            },
        )
        conn.commit()


def get_due_interview_emails(current_time: datetime) -> List[Dict[str, Any]]:
    """
    Fetch scheduled interview emails that are due to be sent.

    Returns rows where:
      - sent = FALSE
      - scheduled_at <= current_time
    """
    with engine.connect() as conn:
        result = conn.execute(
            text(
                """
                SELECT id, job_title, full_name, email, scheduled_at
                FROM scheduled_interview_emails
                WHERE sent = FALSE
                  AND scheduled_at <= :now
                ORDER BY scheduled_at ASC
                LIMIT 200
                """
            ),
            {"now": current_time},
        )
        rows = result.mappings().all()
        return [dict(row) for row in rows]


def mark_interview_email_sent(item_id: int, sent_at: Optional[datetime] = None) -> None:
    """
    Mark an interview-scheduling email as sent.

    item_id: id from scheduled_interview_emails
    sent_at: datetime when the email was actually sent (defaults to now UTC)
    """
    if sent_at is None:
        sent_at = datetime.utcnow()

    with engine.connect() as conn:
        conn.execute(
            text(
                """
                UPDATE scheduled_interview_emails
                SET sent = TRUE,
                    sent_at = :sent_at
                WHERE id = :id
                """
            ),
            {
                "id": item_id,
                "sent_at": sent_at,
            },
        )
        conn.commit()


# -------------------------------------------------------------
# Visitor Logging (visitors)
# -------------------------------------------------------------
def log_visitor(visitor_data: Dict[str, Any]) -> None:
    """
    Log a visitor to the visitors table.

    Your app.py sends a single dict like:

        {
          "visitor_id": str,
          "ip": str,
          "timestamp": "...",
          "first_visit": bool,
          "path": "/careers",
          "referrer": "...",
          "raw_ua": "...",
          "geodata": {...},
          "device": {...},
          "query_params": {...}
        }

    Expected table:

        CREATE TABLE visitors (
          id BIGSERIAL PRIMARY KEY,
          visited_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          ip_address TEXT,
          page_path TEXT,
          referrer_url TEXT,
          user_agent TEXT,
          browser TEXT,
          operating_system TEXT,
          device_type TEXT,
          country TEXT,
          region TEXT,
          city TEXT,
          isp TEXT,
          is_mobile BOOLEAN,
          is_bot BOOLEAN,
          additional_data JSONB
        );
    """
    ip = visitor_data.get("ip")
    page_path = visitor_data.get("path")
    referrer_url = visitor_data.get("referrer")
    user_agent = visitor_data.get("raw_ua")

    device = visitor_data.get("device") or {}
    geodata = visitor_data.get("geodata") or {}

    browser = device.get("browser")
    operating_system = device.get("os")
    device_type = device.get("device")
    is_mobile = device.get("is_mobile")
    is_bot = device.get("is_bot")

    country = geodata.get("country")
    region = geodata.get("regionName")
    city = geodata.get("city")
    isp = geodata.get("isp")

    with engine.connect() as conn:
        try:
            conn.execute(
                text(
                    """
                    INSERT INTO visitors (
                        visited_at,
                        ip_address,
                        page_path,
                        referrer_url,
                        user_agent,
                        browser,
                        operating_system,
                        device_type,
                        country,
                        region,
                        city,
                        isp,
                        is_mobile,
                        is_bot,
                        additional_data
                    ) VALUES (
                        :visited_at,
                        :ip_address,
                        :page_path,
                        :referrer_url,
                        :user_agent,
                        :browser,
                        :operating_system,
                        :device_type,
                        :country,
                        :region,
                        :city,
                        :isp,
                        :is_mobile,
                        :is_bot,
                        :additional_data
                    )
                    """
                ),
                {
                    "visited_at": datetime.utcnow(),
                    "ip_address": ip,
                    "page_path": page_path,
                    "referrer_url": referrer_url,
                    "user_agent": user_agent,
                    "browser": browser,
                    "operating_system": operating_system,
                    "device_type": device_type,
                    "country": country,
                    "region": region,
                    "city": city,
                    "isp": isp,
                    "is_mobile": is_mobile,
                    "is_bot": is_bot,
                    "additional_data": json.dumps(visitor_data),
                },
            )
            conn.commit()
        except Exception as e:
            # Non-fatal: app.py already catches exceptions from log_visitor
            print(f"Error logging visitor: {e}")


# -------------------------------------------------------------
# Admin Dashboard helpers (applications + application_tracking)
# -------------------------------------------------------------
def get_all_applications_with_status() -> List[Dict[str, Any]]:
    """
    Return all applications plus latest interview email + tracking info.

    Joins:
      - applications
      - scheduled_interview_emails (latest per email+job_title)
      - application_tracking (meeting link + last invite)

    IMPORTANT: we do NOT reference a.created_at because your table
    does not have that column. We simply order by a.id DESC.
    """
    with engine.connect() as conn:
        result = conn.execute(
            text(
                """
                WITH latest_scheduled AS (
                  SELECT DISTINCT ON (email, job_title)
                    email,
                    job_title,
                    scheduled_at,
                    sent,
                    sent_at
                  FROM scheduled_interview_emails
                  ORDER BY email, job_title, scheduled_at DESC
                )
                SELECT
                  a.id,
                  a.job_title,
                  a.full_name,
                  a.email,
                  a.country_code,
                  a.phone_number,
                  a.city,
                  a.state,
                  a.country,
                  a.linkedin_url,
                  a.education,
                  a.work_experience,
                  a.resume_url,
                  ls.scheduled_at AS interview_scheduled_at,
                  ls.sent AS interview_email_sent,
                  ls.sent_at AS interview_email_sent_at,
                  at.meeting_link,
                  at.interview_time,
                  at.pipeline_status,
                  at.last_invite_sent_at
                FROM applications a
                LEFT JOIN latest_scheduled ls
                  ON ls.email = a.email AND ls.job_title = a.job_title
                LEFT JOIN application_tracking at
                  ON at.application_id = a.id
                ORDER BY a.id DESC;

                """
            )
        )
        return [dict(row) for row in result.mappings()]


def record_final_invite(
    application_id: int,
    meeting_link: str,
    interview_time: Optional[str] = None,
    pipeline_status: str = "Interview Scheduled",
) -> None:
    """
    Store / update meeting_link, the (optional) interview_time note,
    and mark when the final invite was sent.

    Requires:

        CREATE TABLE application_tracking (
          id BIGSERIAL PRIMARY KEY,
          application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
          meeting_link TEXT,
          interview_time TEXT,
          pipeline_status TEXT,
          last_invite_sent_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE UNIQUE INDEX IF NOT EXISTS application_tracking_application_id_key
          ON application_tracking (application_id);
    """
    with engine.connect() as conn:
        conn.execute(
            text(
                """
                INSERT INTO application_tracking (
                  application_id,
                  meeting_link,
                  interview_time,
                  pipeline_status,
                  last_invite_sent_at,
                  created_at,
                  updated_at
                ) VALUES (
                  :application_id,
                  :meeting_link,
                  :interview_time,
                  :pipeline_status,
                  NOW(),
                  NOW(),
                  NOW()
                )
                ON CONFLICT (application_id) DO UPDATE
                SET meeting_link = EXCLUDED.meeting_link,
                    interview_time = EXCLUDED.interview_time,
                    pipeline_status = COALESCE(EXCLUDED.pipeline_status, application_tracking.pipeline_status),
                    last_invite_sent_at = NOW(),
                    updated_at = NOW();
                """
            ),
            {
                "application_id": application_id,
                "meeting_link": meeting_link,
                "interview_time": interview_time,
                "pipeline_status": pipeline_status,
            },
        )

