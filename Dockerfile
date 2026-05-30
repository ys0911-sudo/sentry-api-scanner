FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright

# Install system libraries required by Playwright's bundled Chromium.
# These are needed even though Docker containers are headless because
# Playwright links against them at startup — the passive mode check will
# detect no display and disable --passive regardless.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
        libcups2 libdrm2 libxkbcommon0 libxcomposite1 \
        libxdamage1 libxfixes3 libxrandr2 libgbm1 \
        libasound2 libpango-1.0-0 libpangocairo-1.0-0 \
        libgtk-3-0 libx11-xcb1 libxcb-dri3-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install chromium

COPY . .
RUN pip install --no-cache-dir -e .

# Run environment detection immediately after install so that
# ~/.sentry/environment.json exists when the container starts.
# In a Docker container DISPLAY and WAYLAND_DISPLAY are not set, so
# detect_and_save() will write {"passive_available": false} and
# --passive will be absent from the CLI inside this container.
RUN python -c \
    "from sentry.config.environment import detect_and_save; detect_and_save()"

RUN mkdir -p /app/reports

ENTRYPOINT ["sentry"]
