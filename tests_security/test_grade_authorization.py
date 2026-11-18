import baseline_secure_coding_api as api

def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username

def test_assigned_professor_can_update_grade(client):
    login(client, "prof_srs", "profpw")

    response = client.post(
    "/grades/update",
    json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )

    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18

def test_student_can_read_own_profile(client):
    login(client, "alice", "alicepw")

    response = client.get(
        "/students/1001/profile"
    )

    assert response.status_code == 200

def test_professor_can_update_assigned_course(client):
    login(client, "prof_srs", "profpw")

    response = client.post(
        "/grades/update",
        json={
            "student_id": 1001,
            "course_id": "SRS",
            "grade": 18,
        },
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "status": "ok",
        "student_id": 1001,
        "course_id": "SRS",
        "grade": 18,
    }

def test_student_can_read_own_profile(client):
    login(client, "alice", "alicepw")

    response = client.get("/students/1001/profile")

    assert response.status_code == 200
    assert response.get_json()["student_id"] == 1001

def test_admin_can_read_student_profile(client):
    login(client, "admin1", "adminpw")

    response = client.get("/students/1001/profile")

    assert response.status_code == 200

def test_student_can_read_own_grades(client):
    login(client, "alice", "alicepw")

    response = client.get("/grades/1001")

    assert response.status_code == 200