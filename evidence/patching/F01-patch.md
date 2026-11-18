1. Root cause
The vulnerability is in POST /grades/update.

The current implementation:
- Reads student_id, course_id and grade from the request.
- Looks up the grade record.
- Updates an existing record or creates a new one without checking the authenticated user's role or assigned courses.
Therefore, the professor prof_srs, whose session contains courses = ["SRS"], can submit course_id = "SSD" and update an existing SSD grade—or potentially create a new grade record for that course.

The root cause is missing server-side authorization at the grade mutation endpoint. The authorization decision must use the authenticated session's course assignments, not the request's course_id alone.
2. Minimal patch
I would keep the endpoint, JSON contract, grade-update behavior, and successful response unchanged. The minimal fix is to enforce the course-assignment check before looking up or modifying the grade record.

F01-patch.diff

Control implemented
The patch enforces:
\[
\text{Professor may update course } C
\iff C \in \text{session.assigned\_courses}
\]

For the confirmed test case:
Session user	Assigned courses	Requested course	Result
prof_srs	SRS	SRS	Allowed
prof_srs	SRS	SSD	403 Forbidden

The check happens before find_grade() and before either modifying an existing grade or appending a new grade, so the authorization failure has no grade-data side effects.
3. Affected paths requiring the same control
From the supplied application, the only grade-mutation path is:
Path	Operation	Assignment check needed?
POST /grades/update	Updates an existing grade	Yes
POST /grades/update	Creates a grade record if none exists	Yes — same endpoint, same check before branching
GET /grades/<student_id>	Reads grades	Not this specific mutation control; it needs its own read-authorization policy
GET /students/<student_id>/profile	Reads student profile	Separate authorization control, already covered by supplied negative tests

There is no separate create-grade endpoint or second grade-update endpoint in the supplied source, so I would not introduce duplicated checks elsewhere.
4. Additional regression tests
The existing test_professor_cannot_update_unassigned_course is the most important regression test and should remain unchanged. The patch should make it pass.

I would add these tests:
A. Professor can update an assigned course

B. Forbidden update does not modify an existing grade
The existing test already verifies that the entire GRADES list remains unchanged. This is excellent and should be retained.
C. Professor cannot create a grade in an unassigned course
This ensures the authorization check protects the GRADES.append() branch as well.

D. Assignment check is independent of student ID
Test that changing student_id does not bypass the course authorization check. Authorization is based on the professor's assigned course, not which student is targeted.
5. Remaining assumptions and limitations
- Professor course assignments are trusted from the authenticated session. This assumes the session is securely signed and the assignment information was populated from a trusted source during login.
- The patch intentionally preserves existing behavior for other roles. It specifically blocks professors from modifying unassigned courses. It does not establish a complete authorization policy for students, administrators, or unauthenticated requests.
- Administrators are not affected by this check. The current code does not define an administrator-specific grade-update policy, so this patch avoids inventing one.
- Course assignment data is assumed to be current. If assignments can change while sessions remain active, stale session data could continue to authorize access until the session is refreshed or invalidated.
- The check applies to both existing and newly created grade records, because it is performed before the mutation branch.
Recommendation
This is a minimal, focused, reviewable patch for the confirmed finding. It introduces one authorization check at the common mutation entry point, preserves the endpoint and success response, and prevents both updating and creating grades for courses not assigned to the professor.

The existing negative test plus the additional tests above should provide good regression coverage without weakening or suppressing any security checks.