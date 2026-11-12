Static Security Review — Academic Services REST API
Security review
Static analysis only
Python / Flask

1. Executive summary
The reviewed source contains several security weaknesses, particularly concerning authentication, authorization, file access and data integrity.

The most significant issue is that the application does not enforce authentication or role-based authorization on its sensitive endpoints. Consequently, an unauthenticated user can retrieve student information, inspect grades, modify grades and potentially download arbitrary files accessible to the application process.

The review covers the complete 159-line Python source file. No code was executed, and no external sources or published vulnerability reports were consulted.
Findings overview
3
Critical / High

4
Medium

1
Low

8
Potential findings



Severity ratings are preliminary and assume the application is accessible to untrusted users. They are not based on an external scoring framework.

2. Findings table
ID	Finding	Affected location	Severity	Confidence
SEC-01	Missing authentication and authorization	/students/<student_id>/profile, get_profile(); /grades/<student_id>, get_grades()	High	High
SEC-02	Unrestricted grade modification	/grades/update, update_grade()	Critical	High
SEC-03	Arbitrary file read / Path traversal	/files, download_file()	High	High
SEC-04	Hardcoded Flask secret key	Application configuration, line 8	Medium	High
SEC-05	Insecure debug configuration	Application startup, line 159	High	High
SEC-06	Missing input validation	update_grade(), get_grades(), get_profile()	Medium	High
SEC-07	Information disclosure through error handling	handle_error(), lines 150–155	Medium	High
SEC-08	Hardcoded plaintext credentials	USERS, lines 36–42	Low / Medium	High


3. Supporting explanations
SEC-01 — Missing authentication and authorization

High
 High confidence

Affected locations:
- get_profile() — lines 115–120.
- get_grades() — lines 122–126.
Code facts

Both endpoints retrieve and return student information without checking whether the requester is authenticated or authorized to access the requested student's information.

For example:
@app.get("/grades/<student_id>")def get_grades(student_id):    sid = int(student_id)    rows = [row for row in GRADES if row["student_id"] == sid]    return flask.jsonify(rows)



The function uses the supplied student_id directly to select records.

Neither endpoint checks the current session, the user's role, or the relationship between the authenticated user and the requested student.

Attacker-controlled input and data flow

An attacker controls the student_id URL parameter.

The parameter is converted to an integer and used to retrieve the corresponding student profile or grade records.

Missing security control and root cause

Missing authentication and object-level authorization.

The application stores user identity and roles in the Flask session during login, but these values are not consulted by the affected endpoints.

Preconditions and potential impact

No authentication is required.

An attacker can:
- Retrieve another student's personal information.
- Retrieve another student's academic records.
- Enumerate student identifiers and access associated records.
This exposes potentially confidential academic and personal information.

Proposed test
1. Start a fresh client without logging in.
2. Request GET /students/1001/profile.
3. Request GET /grades/1001.
4. Verify whether the application returns the records instead of rejecting the requests.
5. Repeat after authenticating as a different student.
Assumptions and uncertainty

The application context establishes that student accounts have associated identifiers and that the system serves multiple users.

I assume student profiles and grades should only be accessible to authorized users. The exact access policy (for example, whether professors can access all students enrolled in their courses) is not specified.

SEC-02 — Unrestricted grade modification

Critical
 High confidence

Affected location:
- update_grade() — lines 128–142.
- Endpoint: POST /grades/update.
Code facts

The endpoint obtains JSON data directly from the request:
data = flask.request.get_json()student_id = data["student_id"]course_id = data["course_id"]grade = data["grade"]



It subsequently inserts or modifies the corresponding record:
row = find_grade(student_id, course_id)if row is None:    GRADES.append({        "student_id": student_id,        "course_id": course_id,        "grade": grade    })else:    row["grade"] = grade



There are no authentication, authorization or ownership checks.

Attacker-controlled input and data flow

An attacker controls all three JSON fields:
- student_id
- course_id
- grade
These values are passed directly to the grade lookup and modification operations.

Missing security control and root cause

The endpoint lacks:
- Authentication enforcement.
- Role-based authorization.
- Course ownership verification.
- Student/course relationship verification.
In particular, the application does not verify whether the requester is a professor assigned to the requested course or an administrator authorized to modify grades.

Preconditions and potential impact

An attacker only needs network access to the endpoint.

Potential consequences include:
- Modifying existing student grades.
- Creating new grade records.
- Changing grades for courses outside a professor's assigned courses.
- Manipulating academic records belonging to other students.
This represents a direct integrity violation affecting academic information.

Proposed test

Submit a POST request without authenticating, containing:
{
  "student_id": 1001,
  "course_id": "SRS",
  "grade": 20
}


Then retrieve the corresponding grade record and verify whether the value has changed.

Repeat with:
- Another student's identifier.
- A course not assigned to the professor.
- A nonexistent student/course combination.
Assumptions and uncertainty

I assume that grade modification must be restricted to authorized professors and administrators.

The exact permission model is not explicitly defined. Nevertheless, the absence of any authorization check is demonstrable.

SEC-03 — Arbitrary file read / Path traversal

High
 High confidence

Affected location:
- download_file() — lines 144–148.
- Endpoint: GET /files.
Code facts

The endpoint constructs a filesystem path using user-controlled input:
raw_path = flask.request.args.get("path", "")target = MATERIALS_DIR / raw_pathreturn flask.send_file(target)



There is no validation or restriction ensuring that the resolved path remains inside MATERIALS_DIR.

Attacker-controlled input and data flow

The attacker controls the path query parameter.

The supplied value is combined with the materials directory and passed directly to flask.send_file().

In Python's path handling, absolute paths can override the preceding directory, while relative paths containing ../ can navigate outside the intended directory.

Missing security control and root cause

The application lacks:
- Path traversal protection.
- Canonical path validation.
- An allowlist of permitted downloadable files.
- Authentication and authorization checks.
The root cause is trusting a user-controlled filesystem path.

Preconditions and potential impact

The endpoint is accessible without authentication.

An attacker may retrieve arbitrary files readable by the application process, subject to filesystem permissions.

Depending on the deployment environment, this could expose:
- Application source code.
- Configuration files.
- Credentials or secrets.
- Other sensitive files accessible to the process.
Proposed test

Attempt requests using:
GET /files?path=../baseline_secure_coding_api.py


And, where supported by the deployment environment, an absolute path to a known readable file outside the materials directory.

Verify whether the application returns file contents.

Assumptions and uncertainty

The finding is based on Python pathlib path-joining semantics and the use of Flask's send_file().

The actual impact depends on filesystem permissions and deployment configuration. Arbitrary file disclosure is possible, but access to any particular sensitive file is not established by the source.

SEC-04 — Hardcoded Flask secret key

Medium
 High confidence

Affected location:

- Application configuration — line 8.

Code facts
app = flask.Flask(__name__)app.config["SECRET_KEY"] = "dev-secret-key"



The Flask secret key is hardcoded and uses an explicitly development-oriented value.

Attacker-controlled input and data flow

An attacker who obtains the application source can obtain the signing secret.

Flask uses this secret to sign session cookies. An attacker possessing the secret can potentially construct valid signed session cookies containing arbitrary session values.

Relevant session values include:
- user
- role
- student_id
- courses
These are populated during login at lines 91–94.

Missing security control and root cause

The application does not use a securely managed, deployment-specific secret.

The root cause is embedding a predictable development secret directly in source code.

Preconditions and potential impact

The attacker needs access to the source or otherwise needs to know the secret.

Potential consequences include:
- Session impersonation.
- Forging arbitrary session identities and roles.
- Manipulating session information returned by /me.
Importantly, the current application does not enforce authorization based on these session values in its sensitive endpoints. Therefore, privilege escalation through a forged administrator session is not independently demonstrated in the current implementation.

Proposed test
1. Authenticate normally and inspect the session cookie.
2. Construct a session containing a different username and role.
3. Sign the modified session using the configured secret.
4. Submit the resulting cookie to /me.
5. Verify whether the application accepts the forged session.
Assumptions and uncertainty

The finding assumes the application uses Flask's default signed-cookie session implementation, which is consistent with the source.

The actual security impact depends on whether the secret is exposed and how session information is trusted elsewhere.

SEC-05 — Insecure debug configuration

High
 High confidence

Affected location:

- Application startup — line 159.

Code facts
app.run(debug=True, host="0.0.0.0", port=5001)



The application starts with debugging enabled and binds to all network interfaces.

Attacker-controlled input and data flow

An attacker can send requests to the application through any network interface reachable on port 5001.

If an unhandled exception occurs, the Werkzeug debugging environment may expose detailed debugging information.

Missing security control and root cause

Debug mode is enabled in the application startup configuration.

The application does not distinguish between development and production execution environments.

Preconditions and potential impact

This finding is particularly relevant if the application is deployed using this startup configuration on an untrusted network.

Potential consequences include:
- Exposure of internal debugging information.
- Disclosure of source code and execution context.
- Potential remote code execution if the interactive debugger is accessible and its protection is bypassed.
Proposed test
1. Start the application using its configured startup command.
2. Access it from another machine on a reachable network.
3. Trigger an unhandled exception.
4. Inspect the resulting error response for debugger exposure.
5. Verify whether the interactive debugger is accessible.
Assumptions and uncertainty

The source establishes that debug mode is enabled and the application binds to 0.0.0.0.

It does not establish that the interactive debugger is externally accessible or that its PIN protection can be bypassed. Remote code execution is therefore a conditional impact, not a demonstrated vulnerability.

SEC-06 — Missing input validation

Medium
 High confidence

Affected locations:
- update_grade() — lines 128–142.
- get_grades() — lines 122–126.
- get_profile() — lines 115–120.
Code facts

The application accepts user-controlled values without comprehensive validation.

For example:
student_id = data["student_id"]course_id = data["course_id"]grade = data["grade"]



No checks enforce:
- Expected data types.
- Valid student identifiers.
- Valid course identifiers.
- Valid grade ranges.
- Valid JSON structure.
Similarly, the GET endpoints use int(student_id) directly without handling invalid identifiers.

Attacker-controlled input and data flow

An attacker can supply malformed JSON, missing fields, unexpected data types, or invalid URL parameters.

These values reach dictionary operations, integer conversions and grade storage.

Missing security control and root cause

The application does not perform schema validation or business-rule validation before processing input.

Preconditions and potential impact

An attacker must be able to reach the relevant endpoint.

Potential consequences include:
- Invalid academic records.
- Inconsistent application state.
- Unexpected exceptions.
- Unnecessary HTTP 500 responses.
- Potential disruption of downstream operations that assume valid data.
For example, a grade represented by an arbitrary string could be stored successfully.

Proposed test

Submit grade-update requests containing:
- Missing JSON fields.
- null values.
- String or object values for grade.
- Negative or excessively large grades.
- Invalid student identifiers.
- Invalid course identifiers.
Verify whether invalid input is rejected or stored.

Also test requests such as:
GET /grades/invalid
GET /students/invalid/profile


Assumptions and uncertainty

The source does not define the accepted grade scale or its validation rules.

A range such as 0–20 should not be treated as a confirmed requirement merely because this is an academic-services application. The expected grade format and valid range must be established by the application's specification.

SEC-07 — Information disclosure through error handling

Medium
 High confidence

Affected location:

- handle_error() — lines 150–155.

Code facts

The application defines a global exception handler:
@app.errorhandler(Exception)def handle_error(exc):    return {        "error": str(exc),        "type": exc.__class__.__name__,    }, 500



It returns the exception message and class name directly to the requester.

Attacker-controlled input and data flow

An attacker can submit malformed requests or parameters that trigger exceptions.

The resulting exception is passed to handle_error(), which exposes its message and type in the HTTP response.

Missing security control and root cause

The application does not separate internal diagnostic information from externally visible error messages.

Preconditions and potential impact

An attacker needs access to an endpoint capable of producing an exception.

Potential consequences include:
- Disclosure of filesystem paths.
- Exposure of internal implementation details.
- Identification of expected data structures.
- Assistance in discovering and exploiting other vulnerabilities.
Proposed test

Trigger exceptions using:
GET /grades/invalid
GET /students/invalid/profile
GET /files?path=nonexistent-file.txt


Inspect the HTTP responses for internal exception messages, filenames, paths or implementation details.

Assumptions and uncertainty

The code definitely exposes exception messages and types.

The exact information disclosed depends on the exception generated and the underlying environment.

SEC-08 — Hardcoded plaintext credentials

Low / Medium
 High confidence

Affected location:
- USERS — lines 36–42.
- login() — lines 82–96.
Code facts

The application defines four accounts directly in source code:
"alice": User(    username="alice",    password="alicepw",    role="student",    student_id=1001)



Passwords are stored as plaintext and compared directly:
if user is None or user.password != password:    return {"error": "invalid credentials"}, 401



Attacker-controlled input and data flow

The attacker supplies a username and password through the login form.

These values are compared directly against the hardcoded account records.

Missing security control and root cause

The application lacks:
- Secure password hashing.
- Externalized credential management.
- Protection against disclosure of credentials embedded in source code.
Preconditions and potential impact

Anyone with access to the source can obtain all configured credentials.

If the application is deployed with these accounts, an attacker may authenticate as a student, professor or administrator.

This is particularly significant for the professor and administrator accounts.

Proposed test
1. Inspect the source for embedded credentials.
2. Submit the corresponding username/password combinations to /login.
3. Verify whether authentication succeeds.
Assumptions and uncertainty

The source explicitly identifies these accounts as demo users through the surrounding context.

If these credentials are exclusively for an isolated teaching exercise, their presence may be intentional. If the application is accessible to untrusted users, they represent a significant authentication weakness.

4. Additional security observations
The following observations are worth recording but are not included as independent vulnerabilities in the findings table.
Observation	Relevant code	Assessment
No login rate limiting	login(), lines 82–96	Repeated password attempts are not restricted in this implementation.
No session clearing during login	login(), lines 91–94	Existing session contents are not explicitly cleared before assigning authenticated values. The practical risk depends on session usage and deployment.
No explicit secure-cookie configuration	Application configuration, line 8	SESSION_COOKIE_SECURE is not explicitly enabled. If deployed over HTTPS, the default configuration does not guarantee that cookies are sent only over HTTPS.
Logout lacks CSRF protection	logout(), lines 98–101	A cross-site POST may force a user's browser to log out, assuming cookie-based authentication and applicable browser cookie settings.
In-memory records	Lines 11–53	This is explicitly an educational simplification, not inherently a security vulnerability.

A particularly important distinction: the absence of an explicit cookie security setting does not establish that the application is deployed over HTTP. Deployment configuration is outside the reviewed source.
5. Overall assessment and priorities
Based exclusively on the reviewed implementation, I would prioritize the following remediation areas before considering the API suitable for use by multiple untrusted users.
Priority	Finding	Recommended security objective
1	SEC-02	Enforce authentication, role authorization and course-level permissions for grade modifications.
2	SEC-03	Restrict file downloads to authorized files within the materials directory.
3	SEC-01	Enforce authentication and object-level authorization for student profiles and grades.
4	SEC-05	Disable debug mode outside controlled development environments.
5	SEC-04	Use a securely generated and managed Flask secret key.
6	SEC-06	Validate request schemas and academic business rules.
7	SEC-07	Return generic error responses and retain diagnostic details internally.
8	SEC-08	Use password hashing and avoid embedded credentials outside isolated demonstrations.

6. Limitations of this review
Several aspects cannot be conclusively evaluated from the supplied source:
- Whether a reverse proxy, gateway or other external component enforces authentication.
- Whether deployment infrastructure restricts network access to the application.
- Whether the application is exposed over HTTP or HTTPS.
- Whether additional authorization policies exist outside this file.
- Whether the sample credentials are intended exclusively for an isolated demonstration.
- The exact academic access-control policy for students, professors and administrators.
- The accepted grade scale and validation requirements.
The findings describe the implementation visible in the supplied file. External controls could mitigate some risks, but their existence cannot be assumed.

Final conclusion: The most serious issues are not subtle implementation flaws: the API currently lacks access-control enforcement on sensitive academic operations and accepts unrestricted filesystem paths for downloads. These should be treated as the primary security concerns.

The review identifies potential vulnerabilities, not experimentally verified exploits. In particular, the proposed tests are intended to validate the findings in a controlled environment; no tests were executed as part of this assessment.