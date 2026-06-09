#!/usr/bin/env python3
import os

os.environ['KEYCLOAK_URL'] = 'http://localhost:8080'
os.environ['KEYCLOAK_REALM'] = 'tinode'
os.environ['KEYCLOAK_CLIENT_ID'] = 'tinode-server'
os.environ['KEYCLOAK_CLIENT_SECRET'] = ''
os.environ['HOST'] = '0.0.0.0'
os.environ['PORT'] = '5000'
os.environ['DEBUG'] = 'False'
os.environ['DB_DSN'] = 'postgres://user:pass@localhost/test'
os.environ['RESTRICTED_TAG_NS'] = 'rest,email,uname'
os.environ['LOGIN_VALIDATION_RE'] = r'^[a-zA-Z0-9_.\-@]{3,64}$'

try:
    from config_example import cfg
    print('✓ Config loaded successfully!')
    print(f'  Keycloak URL: {cfg.keycloak_url}')
    print(f'  Keycloak Realm: {cfg.keycloak_realm}')
    print(f'  Keycloak Client ID: {cfg.keycloak_client_id}')
    secret_status = '(empty is OK for public clients)' if not cfg.keycloak_client_secret else '(configured, not shown)'
    print(f'  Keycloak Client Secret: {secret_status}')
    print(f'  Host: {cfg.host}:{cfg.port}')
    exit(0)
except Exception as e:
    print(f'✗ Error: {e}')
    exit(1)
