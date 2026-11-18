1. Root cause
The confirmed vulnerability is in GET /students/<student_id>/profile, implemented by get_profile().

The current endpoint retrieves a profile based solely on the requested student ID:
@app.get("/students/<student_id>/profile")def get_profile(student_id):    profile = STUDENT_PROFILES.get(int(student_id))    if profile is None:        return {"error": "student not found"}, 404    return flask.jsonify(profile)



There is no authorization check between the authenticated user's session and the requested student profile.

This means a professor can access a student's profile simply by requesting its ID. The existing test also confirms that students should not be able to read another student's profile, so the endpoint needs a consistent ownership/authorization check, not just a professor-specific block.
2. Proposed minimal patch
The patch introduces a reusable authorization helper and applies it to both student-data endpoints:
- GET /students/<student_id>/profile — the confirmed vulnerable endpoint.
- GET /grades/<student_id> — another endpoint exposing student-specific data without an ownership/role check, and therefore requiring the same student-data access control.
The proposed policy is:
Role	Read student profile / grades
Student	Own records only
Professor	Denied
Admin	Allowed
Unauthenticated user	Denied

This preserves legitimate student self-access and administrative access while denying professors access to student records.

Unified diff
F02-patch.diff

3. Authorization control implemented
The helper centralizes the decision instead of duplicating role checks across endpoints:
def can_read_student_data(student_id):    role = flask.session.get("role")    if role == "admin":        return True    if role == "student":        return flask.session.get("student_id") == student_id    return False



The control is deny-by-default:
- Admins are explicitly allowed.
- Students are allowed only when the requested ID matches their session's student_id.
- Professors and any other roles are denied.
- Unauthenticated requests are denied because they have no authorized role.
4. Additional affected paths
Endpoint	Existing issue	Proposed control
GET /students/<student_id>/profile	No authorization; professor can read profiles	Ownership/role check
GET /grades/<student_id>	No authorization; can read any student's grades	Same ownership/role check

I would not automatically apply this helper to GET /files based solely on this finding. That endpoint has a separate file-access vulnerability and requires a different authorization policy—such as permitted file names, roles, or resource ownership—rather than student-record ownership.

Similarly, /grades/update has a separate write-authorization control, which should remain independent of this read-access patch.
5. Suggested regression tests
Profile endpoint
1. Professor cannot read a valid student's profile — 403.
2. Alice can read Alice's profile — 200.
3. Alice cannot read Bob's profile — 403.
4. Admin can read a student's profile — 200.
5. Unauthenticated user cannot read a profile — 403 (or 401, if the API adopts a consistent unauthenticated contract).
6. Non-existent student profile retains the existing 404 response.
Grades endpoint
7. Professor cannot read a student's grades — 403.
8. Alice can read her own grades — 200.
9. Alice cannot read Bob's grades — 403.
10. Admin can read a student's grades — 200.
11. Unauthenticated user cannot read grades — 403 (or consistently 401).
Example test additions
test_student_can_read_own_profile test_admin_can_read_student_profile
test_professor_cannot_read_student_grades test_student_cannot_read_another_students_grades test_student_can_read_own_grades

6. Assumptions and limitations
- Admin access is assumed legitimate: the patch preserves an explicit admin access path. This assumption should be confirmed against the intended authorization policy.
- Professors are denied all student-profile and student-grade reads: if professors are legitimately allowed to access grades for assigned courses, that should be implemented as a more granular policy checking course assignment and the student/course relationship—not by weakening this check.
- Authorization is based on session data: the application currently stores role and student ID in the session during login. This patch relies on those values being correctly established and protected.
- Integer conversion remains unchanged in principle: malformed student_id values can still produce exceptions and the application's generic 500 handler. Input validation is a separate issue and is intentionally not mixed into this patch.
- The profile's existing 404 behavior is preserved: profile existence is checked before authorization. This maintains the current response contract, although it means the endpoint may distinguish nonexistent students from existing students for unauthorized callers.
Recommendation: This is a minimal, reviewable patch that fixes the confirmed profile-access vulnerability and applies the same authorization control to the adjacent student-grades read path, while preserving existing endpoints and legitimate student/admin functionality.