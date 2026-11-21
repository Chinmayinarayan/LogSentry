"""Top-level entrypoint for LogSentry app."""

from signal_app import app, start_consumer
from vault import db
from parse import parser

if __name__ == "__main__":
    db.init_db()
    parser.refresh_config_cache()
    start_consumer()

    print("LogSentry server starting on http://localhost:5050 ...")
    app.run(
        host="0.0.0.0",
        port=5050,
        debug=False,
        use_reloader=False
    )