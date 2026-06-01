"""
sentry/config/__init__.py

Package initialiser for the sentry.config subpackage. This package holds all
static configuration that does not change at runtime: security header rule
definitions, default YAML settings, and the install-time environment detection
module. No application logic lives here.

Modules:
    environment: Detects display availability at install time and caches the result.
    headers: Defines RECOMMENDED_HEADERS, HARMFUL_HEADERS, and scoring constants.
    defaults.yaml: Default runtime settings loaded by the main config loader.
"""
