
from fastapi.testclient import TestClient

from app.api.main import app


client = TestClient(app)


def test_health():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "RDRS REST API"


def test_status():
    response = client.get("/status")

    assert response.status_code == 200

    data = response.json()

    assert data["system"] == "RDRS"
    assert data["status"] == "running"
    assert "statistics" in data


def test_alerts():
    response = client.get("/alerts")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "alerts" in data
    assert isinstance(data["alerts"], list)


def test_events():
    response = client.get("/events")

    assert response.status_code == 200

    data = response.json()

    assert "count" in data
    assert "events" in data
    assert isinstance(data["events"], list)


def test_reports():
    response = client.get("/reports")

    assert response.status_code == 200

    data = response.json()

    assert "incidents" in data
    assert "scores" in data
    assert isinstance(data["incidents"], list)
    assert isinstance(data["scores"], list)


def test_scan():
    response = client.post("/scan")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "completed"
    assert "files_scanned" in data
    assert "suspicious_files" in data
    assert data["mode"] == "safe_read_only"


def test_settings_valid():
    response = client.post(
        "/settings",
        json={
            "entropy_threshold": 7.0,
            "rapid_change_threshold": 10,
            "rename_threshold": 3,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "accepted"
    assert data["settings"]["entropy_threshold"] == 7.0


def test_settings_invalid_entropy():
    response = client.post(
        "/settings",
        json={
            "entropy_threshold": 15,
            "rapid_change_threshold": 10,
            "rename_threshold": 3,
        },
    )

    assert response.status_code == 422

