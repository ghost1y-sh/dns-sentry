#!/usr/bin/env python3

"""Flask application factory for dns-sentry."""

import os
from flask import Flask
from dotenv import load_dotenv


load_dotenv()


def create_app():
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    )

    app.config["VT_API_KEY"] = os.environ.get("VT_API_KEY", "")
    app.config["REDIS_HOST"] = os.environ.get("REDIS_HOST", "localhost")
    app.config["REDIS_PORT"] = int(os.environ.get("REDIS_PORT", 6379))

    from app.routes import bp
    app.register_blueprint(bp)

    return app