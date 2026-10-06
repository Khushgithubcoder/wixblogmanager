"""
Run the due-post publisher once and exit. Use this from an external scheduler (e.g. a Render
Cron Job: `python backend/run_scheduler.py`, every minute) so scheduled posts go out even
when the web service is asleep. Set ENABLE_INAPP_SCHEDULER=0 on the web service in that case.
"""
import os

os.environ["ENABLE_INAPP_SCHEDULER"] = "0"  # don't start the loop thread when importing app

from app import process_due_blogs  # noqa: E402

if __name__ == "__main__":
    process_due_blogs()
