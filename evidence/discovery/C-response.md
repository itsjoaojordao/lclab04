Static Security Review — Academic Services REST API
Scope: baseline_secure_coding_api(3).py
Review type: Static application security analysis
Reference: Requirements R1–R7 supplied in the request.

The review identifies seven security findings. The most significant problems concern missing authentication and authorization controls, unrestricted grade modifications, and unrestricted filesystem access.

No code was executed, and no external sources or published solutions were used. Findings are based exclusively on the supplied Python source and application context.
1. Findings summary
ID	Finding	Affected location	Severity	Confidence
F-01	Missing authentication and authorization on student profiles	get_profile() — L115–120	High	High
F-02	Unrestricted grade retrieval and information disclosure	get_grades() — L122–126	High	High
F-03	Unrestricted grade modification and insufficient validation	update_grade() — L128–142	Critical	High
F-04	Path traversal and unauthenticated file access	download_file() — L144–148	Critical	High
F-05	Exposure of internal exception information	handle_error() — L150–155	Medium	High
F-06	Predictable Flask session signing secret	Application configuration — L7	High	High
F-07	Hardcoded plaintext account credentials	USERS — L36–43; login() — L82–95	Medium	High

Severity reflects the potential impact under the supplied application context, rather than evidence that an attack has already occurred.

2. Supporting explanations
F-01 — Missing authentication and authorization on student profiles

High severity
 High confidence

Affected location:
- File: baseline_secure_coding_api(3).py
- Function: get_profile()
- Lines: 115–120
Relevant requirements: R1, R2, R3, R4.

1. Attacker-controlled input and data flow

The endpoint accepts a student identifier directly through the URL:
@app.get("/students/<student_id>/profile")def get_profile(student_id):    profile = STUDENT_PROFILES.get(int(student_id))



The supplied identifier is converted to an integer and used to retrieve a profile.

There is no authentication check or authorization decision before accessing the profile.

2. Missing security control and root cause

The endpoint does not verify:
- Whether the requester is authenticated.
- Whether the requester is a student, professor, or administrator.
- Whether a student is accessing their own profile.
- Whether an administrator is accessing the record.
Additionally, professors are not explicitly prevented from accessing student profiles.

The root cause is the absence of server-side access-control enforcement in the endpoint.

3. Preconditions and potential impact

An attacker only needs network access to the API.

Potential consequences include:
- Unauthorized access to student personal information.
- Disclosure of names, email addresses and academic programmes.
- Access to profiles belonging to other students.
- Disclosure of student profiles to professors, contrary to R3.
4. Proposed verification test
1. Send a request without authentication:
   
   GET /students/1001/profile
2. Authenticate as student Alice and request Bob's profile:
   
   GET /students/1002/profile
3. Authenticate as professor prof_srs and request either student's profile.
4. Authenticate as administrator and request both profiles.
Expected behaviour:
Requester	Requested profile	Expected result
Unauthenticated	Any	401
Alice	Alice	200
Alice	Bob	403
Professor	Any student	403
Administrator	Any student	200

5. Assumptions and confidence

The authorization rules are explicitly established by R1–R3. The absence of authorization checks in the supplied function is directly demonstrable.

Confidence: High.

F-02 — Unrestricted grade retrieval and information disclosure

High severity
 High confidence

Affected location:
- File: baseline_secure_coding_api(3).py
- Function: get_grades()
- Lines: 122–126
Relevant requirements: R1, R2, R3, R4.

1. Attacker-controlled input and data flow

The endpoint receives a student identifier:
@app.get("/grades/<student_id>")def get_grades(student_id):    sid = int(student_id)    rows = [row for row in GRADES if row["student_id"] == sid]    return flask.jsonify(rows)



The identifier determines which records are retrieved from the global GRADES collection.

2. Missing security control and root cause

The implementation does not perform authentication or authorization.

More importantly, the returned records are filtered exclusively by student identifier.

There is no verification that:
- A student is requesting their own grades.
- A professor is requesting grades belonging to an assigned course.
- An administrator is requesting the records.
The implementation also does not filter professor results by assigned courses.

3. Preconditions and potential impact

An attacker needs network access but does not need valid credentials.

Potential consequences:
- Disclosure of any student's grades.
- Disclosure of grades for courses outside a professor's responsibility.
- Unauthorized access to academic performance information.
For example, the professor assigned only to SRS could retrieve the SSD grade of student 1001.

4. Proposed verification test

Test the following requests:
- Unauthenticated user requests /grades/1001.
- Alice requests /grades/1002.
- Professor prof_srs requests /grades/1001.
- Administrator requests /grades/1001.
Expected behaviour:
- Unauthenticated requests return 401.
- Students receive only their own grades.
- Professors receive only grades belonging to their assigned courses.
- Administrators can retrieve all grades.
- Requests without permitted records are denied rather than returning unauthorized records.
5. Assumptions and confidence

The course-assignment restriction is explicitly established by R3.

The fact that the implementation returns every grade matching the supplied student identifier is directly demonstrable.

Confidence: High.

F-03 — Unrestricted grade modification and insufficient validation

Critical severity
 High confidence

Affected location:
- File: baseline_secure_coding_api(3).py
- Function: update_grade()
- Lines: 128–142
Relevant requirements: R1, R3, R4, R5, R7.

1. Attacker-controlled input and data flow

The endpoint accepts JSON input:
@app.post("/grades/update")def update_grade():    data = flask.request.get_json()    student_id = data["student_id"]    course_id = data["course_id"]    grade = data["grade"]



All three values are subsequently used to identify or create a grade record.

The application then executes:
row = find_grade(student_id, course_id)if row is None:    GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})else:    row["grade"] = grade



2. Missing security control and root cause

There are several independent problems.

A. Missing authentication and authorization

There is no verification that the requester is authenticated.

There is also no role or course-assignment verification.

Consequently, any requester can attempt to modify any grade.

B. Missing input validation

The implementation does not verify:
- That student_id is a positive integer.
- That the student exists.
- That course_id is one of the known courses (SRS or SSD).
- That grade is numeric.
- That the grade is between 0 and 20.
- That the grade is not a boolean value.
- That all required fields are present and correctly structured.
C. Unrestricted record creation

When no existing record is found, the implementation automatically appends a new record.

This allows arbitrary student identifiers and course identifiers to be introduced into the grade collection.

D. Boolean values accepted as grades

Python treats boolean values as a subclass of integers.

Because the implementation does not explicitly reject booleans, values such as true and false can be stored as grades.

3. Preconditions and potential impact

The endpoint is directly accessible without authentication.

Potential consequences include:
- Unauthorized modification of academic results.
- Modification of grades belonging to other students.
- Modification of grades outside a professor's assigned courses.
- Creation of records for nonexistent students.
- Creation of records for unknown courses.
- Storage of invalid academic grades.
- Corruption of academic data.
This is particularly significant because the application modifies shared in-memory records.

4. Proposed verification test

Perform the following tests, inspecting GRADES before and after each request.
Test	Example input or condition	Expected result
Unauthenticated update	Valid JSON	401
Student modifies another student's grade	Valid JSON	403
Professor modifies SSD grade	Professor assigned only SRS	403
Unknown student	student_id: 9999	Client error
Unknown course	course_id: "ABC"	Client error
Negative grade	grade: -1	Client error
Grade above maximum	grade: 21	Client error
Boolean grade	grade: true	Client error
Missing field	Omit grade	Client error
Invalid JSON	Malformed JSON	Client error

For every denied or invalid update, verify that the original GRADES collection remains unchanged.

Also verify that an administrator can update an existing valid record and create a valid record if that operation is intended by the baseline requirements.

5. Assumptions and confidence

All validation and authorization requirements are explicitly specified in R1, R3 and R5.

The absence of the corresponding controls is directly demonstrable.

The impact on academic records assumes that the application exposes this endpoint to an attacker who can submit requests.

Confidence: High.

F-04 — Path traversal and unauthenticated file access

Critical severity
 High confidence

Affected location:
- File: baseline_secure_coding_api(3).py
- Function: download_file()
- Lines: 144–148
Relevant requirements: R1, R6, R7.

1. Attacker-controlled input and data flow

The endpoint accepts a file path through a query parameter:
raw_path = flask.request.args.get("path", "")target = MATERIALS_DIR / raw_pathreturn flask.send_file(target)



The attacker controls raw_path.

The application combines this value with MATERIALS_DIR and passes the resulting path directly to Flask's file-serving functionality.

2. Missing security control and root cause

Two important controls are missing.

A. Missing authentication

The endpoint does not verify whether the requester has an authenticated session.

B. Missing filesystem boundary enforcement

The application does not verify that the resolved target remains inside MATERIALS_DIR.

Using the / operator with pathlib.Path does not guarantee containment. In particular, an absolute path supplied by the requester can override the base directory.

Relative paths containing directory traversal components can also escape the materials directory.

No explicit path containment check or equivalent restriction is implemented.

3. Preconditions and potential impact

An attacker needs network access to the endpoint.

Potential consequences include:
- Unauthorized downloads of files outside the materials directory.
- Disclosure of configuration files.
- Exposure of application source code.
- Exposure of other readable files on the server.
- Disclosure of sensitive information if accessible files contain it.
The actual impact depends on the filesystem permissions and files available to the application process.

4. Proposed verification test

Test the following requests:
1. Download an existing teaching material without authentication:
   
   GET /files?path=srs-summary.txt
2. Attempt directory traversal:
   
   GET /files?path=../baseline_secure_coding_api(3).py
3. Attempt an absolute filesystem path, using a known readable test file outside the materials directory.
Expected behaviour:
- Unauthenticated requests return 401.
- Authenticated requests can download permitted materials.
- Attempts to access files outside the materials directory are rejected.
- No external file contents are returned.
5. Assumptions and confidence

The absence of authentication and path containment validation is directly demonstrable.

The exact files an attacker could retrieve depend on the deployment filesystem and process permissions.

Confidence: High.

F-05 — Exposure of internal exception information

Medium severity
 High confidence

Affected location:
- File: baseline_secure_coding_api(3).py
- Function: handle_error()
- Lines: 150–155
Relevant requirements: R5, R7.

1. Attacker-controlled input and data flow

The application defines a global exception handler:
@app.errorhandler(Exception)def handle_error(exc):    return {        "error": str(exc),        "type": exc.__class__.__name__,    }, 500



Several endpoints process attacker-controlled values using operations that can raise exceptions.

Examples include:
- int(student_id) in get_profile().
- int(student_id) in get_grades().
- request.get_json() in update_grade().
- Dictionary access using data["student_id"], data["course_id"] and data["grade"].
- File access through send_file().
2. Missing security control and root cause

The exception handler returns internal exception information directly to the requester.

This can expose:
- Internal filesystem paths.
- Exception types.
- Implementation details.
- Information about the application's internal operations.
Furthermore, the handler converts all caught exceptions into HTTP 500 responses, including exceptions caused by malformed client input.

This is inconsistent with the requirement to return appropriate client errors.

3. Preconditions and potential impact

An attacker needs to submit an input that triggers an exception.

Potential consequences include:
- Disclosure of internal filesystem locations.
- Information useful for preparing further attacks.
- Incorrect HTTP status codes.
- Exposure of implementation details that should remain internal.
4. Proposed verification test

Submit requests such as:
- /students/invalid/profile
- /grades/invalid
- A grade-update request with missing JSON fields.
- A file-download request for a nonexistent file.
Inspect the HTTP status codes and response bodies.

Expected behaviour:
- Malformed inputs return appropriate 4xx responses.
- Responses do not expose exception messages, internal paths or implementation details.
- Unexpected internal failures return a generic 500 response.
5. Assumptions and confidence

The disclosure of exception messages is directly demonstrable.

Whether a particular request reveals a filesystem path depends on the exception generated.

Confidence: High.

F-06 — Predictable Flask session signing secret

High severity
 High confidence

Affected location:
- File: baseline_secure_coding_api(3).py
- Application configuration
- Line: 8
Relevant requirements: R1, R3, R4.

1. Attacker-controlled input and data flow

The application configures its Flask secret key as follows:
app.config["SECRET_KEY"] = "dev-secret-key"



During login, information about the authenticated user is stored in the Flask session:
flask.session["user"] = user.usernameflask.session["role"] = user.roleflask.session["student_id"] = user.student_idflask.session["courses"] = user.courses or []



Flask's default session mechanism uses a cryptographic signature to protect cookie-based session data.

2. Missing security control and root cause

The application uses a fixed, predictable secret instead of a sufficiently random secret managed outside the source code.

If an attacker knows this secret, they can potentially construct validly signed session cookies containing attacker-selected session values.

These values include the username, role, student identifier and assigned courses.

The root cause is the use of a development secret as the application's session signing key.

An important distinction: the current implementation does not actually enforce authorization using these session values in the protected endpoints. Therefore, session forgery is a demonstrated weakness in session integrity, but it is not necessary to exploit the existing missing-access-control vulnerabilities identified in F-01 through F-04.

3. Preconditions and potential impact

An attacker must know the signing secret, which is directly visible in the supplied source.

Potential consequences include:
- Forged session identities.
- Manipulation of session roles and student identifiers.
- Impersonation of other accounts at the session level.
- Privilege escalation if endpoints rely on the forged session information for authorization.
4. Proposed verification test

Using an isolated test instance:
1. Authenticate as a normal student.
2. Inspect the session cookie.
3. Attempt to construct a session containing an administrator role using the configured signing secret.
4. Submit the resulting cookie to /me.
5. Verify whether the application accepts the forged session.
Expected behaviour for a properly protected deployment is that clients cannot forge authenticated session contents.

5. Assumptions and confidence

The fixed secret is directly visible in the source.

The ability to forge session cookies follows from the application's use of Flask's default signed-cookie sessions.

The actual impact on protected operations depends on authorization enforcement, which is independently missing in the current implementation.

Confidence: High.

F-07 — Hardcoded plaintext account credentials

Medium severity
 High confidence

Affected location:
- File: baseline_secure_coding_api(3).py
- Global variable: USERS
- Lines: 36–43
- Function: login()
- Lines: 82–95
Relevant requirements: R1.

1. Attacker-controlled input and data flow

The application defines user accounts directly in its source:
USERS = {    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),    ...}



The login function retrieves the corresponding account and compares the supplied password directly:
user = USERS.get(username)if user is None or user.password != password:    return {"error": "invalid credentials"}, 401



2. Missing security control and root cause

Credentials are stored as plaintext rather than password hashes.

Additionally, account credentials are embedded in the application source code.

Anyone with access to the source can obtain the configured credentials without performing a password attack.

The root cause is the use of hardcoded demo credentials and plaintext password storage.

3. Preconditions and potential impact

An attacker needs access to the source code or another disclosure mechanism exposing the credentials.

Potential consequences include:
- Unauthorized account access.
- Impersonation of students, professors or administrators.
- Access to information and functionality associated with compromised accounts.
The impact is particularly significant for the administrator account.

4. Proposed verification test

Inspect the source and confirm that the account passwords are stored as readable strings.

As a functional test, authenticate using the supplied account credentials and verify that the corresponding account is accessible.

For a more realistic security assessment, verify that application credentials are not recoverable from the deployed source or configuration.

5. Assumptions and confidence

The plaintext credentials are directly demonstrable.

However, the supplied context describes a simplified teaching environment. It is possible that these credentials are intentionally provided as demonstration accounts.

Consequently, this finding represents a security weakness if the same approach is retained outside the controlled teaching environment.

Confidence: High regarding the implementation; medium regarding its practical deployment impact.

3. Requirements coverage
The following table maps the identified findings to the supplied security requirements.
Requirement	Result	Related findings
R1 — Authentication	Fail	F-01, F-02, F-03, F-04
R2 — Student privacy	Fail	F-01, F-02
R3 — Academic staff scope	Fail	F-01, F-02, F-03
R4 — Complete authorization	Fail	F-01, F-02, F-03
R5 — Input validation	Fail	F-03, F-05
R6 — File access	Fail	F-04
R7 — Error handling	Fail	F-03, F-04, F-05

4. Overall assessment
Security posture: Significant weaknesses identified
The application does not currently enforce several of the explicitly defined security requirements. The most serious issues are missing authorization checks and unrestricted access to sensitive operations.

Highest-priority findings
1. F-03 — Unrestricted grade modification.
2. F-04 — Path traversal and unauthenticated file access.
3. F-01 — Unauthorized student profile access.
4. F-02 — Unauthorized grade retrieval.
5. F-06 — Predictable session signing secret.

Recommended remediation order (without implementing patches):
1. Establish centralized authentication and authorization checks, applied independently to every protected endpoint.
2. Implement record-level authorization, including student ownership and professor course assignments.
3. Enforce strict grade-update validation before modifying shared records.
4. Restrict file access to authenticated requests and enforce filesystem path containment.
5. Replace detailed exception responses with controlled client errors and generic internal error responses.
6. Replace the predictable session secret with a securely generated deployment-specific secret.
7. Remove hardcoded plaintext credentials and introduce appropriate credential storage.
Important limitation: This is a static review of one source file. It does not establish whether additional protections exist in deployment infrastructure, reverse proxies, middleware, or other components not supplied. Equally, the absence of additional findings does not establish that the application is secure.

The findings above distinguish directly observable implementation weaknesses from their potential consequences and deployment-dependent assumptions. No patches have been generated.