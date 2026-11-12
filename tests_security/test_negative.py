import baseline_secure_coding_api as api
import copy

def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username

def test_professor_cannot_update_unassigned_course(client):
    login(client, "prof_srs", "profpw")

    original_grades = copy.deepcopy(api.GRADES)

    response = client.post(
        "/grades/update",
        json={
            "student_id": 1001,
            "course_id": "SSD",
            "grade": 18
        }
    )

    assert response.status_code == 403
    assert api.GRADES == original_grades

def test_professor_cannot_read_student_profile(client):
    login(client, "prof_srs", "profpw")

    response = client.get(
        "/students/1001/profile"
    )

    assert response.status_code == 403

def test_student_cannot_read_another_student_profile(client):
    login(client, "alice", "alicepw")

    response = client.get(
        "/students/1002/profile"
    )

    assert response.status_code == 403