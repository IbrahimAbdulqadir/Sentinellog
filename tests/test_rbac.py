"""
Tests for multi-tenant RBAC: owner accounts see everything (matching the
original single-admin behavior), member accounts are scoped to exactly one
Client and can't see or reach another client's sessions/alerts/blocks.
"""
import os
import tempfile

import pytest
from werkzeug.security import generate_password_hash

# DATABASE_URL must be set BEFORE app.py is imported: Flask-SQLAlchemy binds its
# engine to whatever SQLALCHEMY_DATABASE_URI is in app.config the first time the
# DB is touched, and app.py sets that config at import time. Overriding
# app.config afterward does nothing — the engine is already bound — so without
# this, these tests would silently read and write the real sentinellog.db.
_db_fd, _db_path = tempfile.mkstemp(suffix='.db')
os.environ['DATABASE_URL'] = 'sqlite:///' + _db_path
os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('ENCRYPTION_KEY', 'kX9m2vQvW6yj0s3zP8bN1cR4tL7hF5dA2gU9xE6qYzM=')
os.environ.setdefault('ADMIN_USERNAME', 'admin')
os.environ.setdefault('ADMIN_PASSWORD', 'test-owner-password')

import app as app_module
from models import db, AdminUser, MonitorSession, Client


@pytest.fixture(scope='module')
def client():
    """
    Module-scoped: seeded once, shared by every test in this file. Tests that
    add their own rows use names that don't collide with the seed data or
    each other.
    """
    app_module.app.config['TESTING'] = True
    app_module.init_db()

    with app_module.app.app_context():
        c1 = Client(name='Acme')
        c2 = Client(name='Globex')
        db.session.add_all([c1, c2])
        db.session.commit()

        db.session.add_all([
            AdminUser(username='acme_user', password_hash=generate_password_hash('pw1'),
                      role='member', client_id=c1.id),
            AdminUser(username='globex_user', password_hash=generate_password_hash('pw2'),
                      role='member', client_id=c2.id),
        ])
        db.session.add_all([
            MonitorSession(id='sess1', target_name='Acme box', client_id=c1.id, filepath='', mode='replay'),
            MonitorSession(id='sess2', target_name='Globex box', client_id=c2.id, filepath='', mode='replay'),
        ])
        db.session.commit()

    with app_module.app.test_client() as test_client:
        yield test_client

    with app_module.app.app_context():
        db.engine.dispose()
    os.close(_db_fd)
    try:
        os.unlink(_db_path)
    except PermissionError:
        # Windows can still be holding the file open via a daemon worker thread
        # started by a 'replay'/'tail' session in one of the tests above — not
        # worth synchronizing on just to delete a temp file the OS will reclaim.
        pass


def login(test_client, username, password):
    # /login redirects immediately if someone's already authenticated, so a
    # shared test client switching accounts between tests has to log out first
    # or the POST below silently no-ops and leaves the previous user logged in.
    test_client.get('/logout')
    return test_client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)


def test_member_sees_only_their_own_client_sessions(client):
    login(client, 'acme_user', 'pw1')
    res = client.get('/api/sessions')
    ids = [s['id'] for s in res.get_json()]
    assert ids == ['sess1']


def test_owner_sees_every_clients_sessions(client):
    login(client, 'admin', 'test-owner-password')
    res = client.get('/api/sessions')
    ids = {s['id'] for s in res.get_json()}
    assert ids == {'sess1', 'sess2'}


def test_member_cannot_open_another_clients_monitor_page(client):
    login(client, 'acme_user', 'pw1')
    res = client.get('/monitor/sess2')
    assert res.status_code == 404


def test_member_can_open_their_own_monitor_page(client):
    login(client, 'acme_user', 'pw1')
    res = client.get('/monitor/sess1')
    assert res.status_code == 200


def test_member_cannot_stop_another_clients_session(client):
    login(client, 'acme_user', 'pw1')
    res = client.post('/api/monitor/stop/sess2')
    assert res.status_code == 404
    with app_module.app.app_context():
        row = db.session.get(MonitorSession, 'sess2')
        assert row.running is False  # unaffected, not merely denied after acting


def test_member_cannot_manage_clients(client):
    login(client, 'acme_user', 'pw1')
    res = client.get('/admin/clients')
    assert res.status_code == 404
    res = client.post('/api/clients', json={'name': 'New Co'})
    assert res.status_code == 404


def test_owner_can_create_client_and_scoped_member(client):
    login(client, 'admin', 'test-owner-password')
    res = client.post('/api/clients', json={'name': 'Initech'})
    assert res.status_code == 200
    new_client_id = res.get_json()['id']

    res = client.post(f'/api/clients/{new_client_id}/users',
                       json={'username': 'initech_user', 'password': 'pw3'})
    assert res.status_code == 200

    with app_module.app.app_context():
        user = AdminUser.query.filter_by(username='initech_user').first()
        assert user.role == 'member'
        assert user.client_id == new_client_id


def test_member_cannot_assign_session_to_another_client(client):
    login(client, 'acme_user', 'pw1')
    res = client.post('/api/monitor/start', json={
        'target_name': 'sneaky', 'mode': 'replay', 'filepath': 'sample_logs/auth.log',
        'client_id': 999,  # Globex's id, or anything else — must be ignored
    })
    assert res.status_code == 200
    session_id = res.get_json()['session_id']
    with app_module.app.app_context():
        row = db.session.get(MonitorSession, session_id)
        acme = AdminUser.query.filter_by(username='acme_user').first()
        assert row.client_id == acme.client_id
