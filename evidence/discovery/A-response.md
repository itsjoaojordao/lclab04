Static Security Review — Baseline Secure Coding API
Multiple security issues identified
Static analysis only

1. Executive summary
The reviewed application, baseline_secure_coding_api.py, is a small Flask REST API implementing authentication, student profiles, grade management and file downloads.

The source contains several potentially exploitable security weaknesses, particularly concerning access control, authentication, file handling and session security.

The most significant issues are:
- Unauthenticated and unauthorized modification of student grades.
- Insecure direct object references (IDOR) and missing authorization checks.
- Path traversal in the file download endpoint.
- Hardcoded credentials and a hardcoded Flask session signing key.
- Debug mode enabled on a server listening on all network interfaces.
The review is based exclusively on the supplied source code. No code was executed, no external resources were consulted, and no vulnerabilities were dynamically verified.
2. Findings summary
The following table summarizes the identified potential vulnerabilities.
ID	Finding	Affected location	Severity	Confidence
SEC-01	Missing authorization on grade modification	update_grade() — L128–142	Critical	High
SEC-02	Unauthenticated access to student information	get_profile() — L115–120; get_grades() — L122–126	High	High
SEC-03	Path traversal in file downloads	download_file() — L144–148	High	High
SEC-04	Hardcoded Flask secret key	Application configuration — L7–8	High	High
SEC-05	Hardcoded plaintext user credentials	USERS — L36–43	High	High
SEC-06	CSRF protection missing	login(), logout(), update_grade() — L82–142	Medium	Medium
SEC-07	Flask debug mode enabled	Application startup — L158–159	Critical	High
SEC-08	Sensitive exception information disclosure	handle_error() — L150–155	Medium	High
SEC-09	Insufficient input validation	update_grade(), get_profile(), get_grades() — L115–142	Medium	High

Severity represents potential impact under the assumption that the application is deployed in an environment where untrusted users can access its endpoints. It is not a formal CVSS assessment.

3. Detailed findings
SEC-01 — Missing authorization on grade modification

Critical
 High confidence

Affected location:
- File: baseline_secure_coding_api.py
- Function: update_grade()
- Lines: 128–142
1. Description and execution path

The /grades/update endpoint accepts a JSON request containing three parameters:
- student_id
- course_id
- grade
The application then searches for an existing grade and either modifies it or inserts a new record.
@app.post("/grades/update")def update_grade():    data = flask.request.get_json()    student_id = data["student_id"]    course_id = data["course_id"]    grade = data["grade"]    row = find_grade(student_id, course_id)    if row is None:        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})    else:        row["grade"] = grade



There are no authentication or authorization checks before modifying the database.

2. Attacker-controlled input and data flow

An attacker can directly supply all three JSON parameters.

The execution path is:

HTTP POST /grades/update → JSON parsing → find_grade() → modification or insertion into GRADES.

The endpoint does not check whether the requester is authenticated, whether their role is professor or admin, or whether they are authorized to modify the specified student's grade.

3. Missing security control and root cause

The application lacks server-side authorization enforcement.

Although the login endpoint stores the user's role and other information in the Flask session, those values are never consulted by update_grade().

The root cause is the absence of access-control enforcement at the operation that modifies sensitive information.

4. Preconditions and potential impact

Precondition: The attacker must be able to reach the endpoint.

Potential impacts:
- Unauthorized modification of existing grades.
- Insertion of fraudulent grades.
- Manipulation of academic records.
- Potential compromise of academic data integrity.
5. Proposed test

Send a POST request to /grades/update without authenticating.

Use a JSON body such as:
{
    "student_id": 1001,
    "course_id": "SRS",
    "grade": 20
}


Verify whether the application accepts the request and changes Alice's grade.

Repeat using an authenticated student account.

6. Assumptions and confidence

The absence of authentication and authorization checks is directly demonstrated by the source.

The security requirement that only professors or administrators should modify grades is an assumption based on the application's apparent academic context. The exact authorization policy is not provided.

Confidence: High.

SEC-02 — Unauthenticated access to student information

High
 High confidence

Affected locations:
- Function: get_profile() — Lines 115–120.
- Function: get_grades() — Lines 122–126.
1. Description and execution path

Both endpoints expose student-related information without checking whether the requester is authenticated.

For example:
@app.get("/students/<student_id>/profile")def get_profile(student_id):    profile = STUDENT_PROFILES.get(int(student_id))    if profile is None:        return {"error": "student not found"}, 404    return flask.jsonify(profile)



Similarly:
@app.get("/grades/<student_id>")def get_grades(student_id):    sid = int(student_id)    rows = [row for row in GRADES if row["student_id"] == sid]    return flask.jsonify(rows)



Neither endpoint accesses flask.session or performs an authorization check.

2. Attacker-controlled input and data flow

The attacker controls student_id through the URL.

The execution paths are:
- /students/1001/profile → profile lookup → profile disclosure.
- /grades/1001 → grade filtering → grade disclosure.
The attacker can also change the identifier to access another student's information.

3. Missing security control and root cause

The application does not enforce authentication or ownership-based authorization.

This also creates an IDOR-style vulnerability: the application directly trusts an identifier supplied by the requester without checking whether that requester is entitled to access the corresponding record.

4. Preconditions and potential impact

Precondition: Network access to the endpoints.

Potential impacts:
- Disclosure of student names and email addresses.
- Unauthorized access to academic grades.
- Enumeration of student records.
- Potential privacy violations.
5. Proposed test

Without logging in, request:
GET /students/1001/profile
GET /grades/1001
GET /grades/1002


Verify whether the endpoints return the corresponding records.

Repeat while authenticated as a student and attempt to access another student's information.

6. Assumptions and confidence

The lack of authentication and authorization checks is demonstrated by the source.

Whether student profiles or grades are intended to be publicly accessible is unknown. The finding assumes these academic records require restricted access.

Confidence: High.

SEC-03 — Path traversal in file downloads

High
 High confidence

Affected location:
- Function: download_file()
- Lines: 144–148.
1. Description and execution path

The /files endpoint accepts a filename through a query parameter and constructs a filesystem path.
@app.get("/files")def download_file():    raw_path = flask.request.args.get("path", "")    target = MATERIALS_DIR / raw_path    return flask.send_file(target)



The application does not validate or sanitize the supplied path.

2. Attacker-controlled input and data flow

The attacker controls the path query parameter.

The execution path is:

GET /files?path=... → request.args.get() → filesystem path construction → flask.send_file().

Because the application directly combines the materials directory with the supplied path, an attacker may use path traversal sequences such as ../ to reference files outside the intended directory.

Absolute paths may also override the base directory when used as the second operand of pathlib.Path.

3. Missing security control and root cause

There is no validation that the resolved target remains inside MATERIALS_DIR.

The root cause is trusting user-controlled filesystem paths without enforcing directory confinement.

4. Preconditions and potential impact

Preconditions:
- The attacker can access /files.
- The application process has read permissions on the targeted files.
Potential impacts:
- Unauthorized disclosure of files outside the materials directory.
- Exposure of configuration files, application source code or other sensitive information.
- Potential disclosure of secrets stored in readable files.
5. Proposed test

Attempt to request:
GET /files?path=../baseline_secure_coding_api.py


Also test an absolute path to a known readable file outside MATERIALS_DIR.

Verify whether the application returns the requested file or rejects the request.

6. Assumptions and confidence

The lack of path validation is directly demonstrated.

Successful exploitation depends on filesystem permissions, operating-system path semantics and the deployment environment.

Confidence: High.

SEC-04 — Hardcoded Flask secret key

High
 High confidence

Affected location:
- Application configuration.
- Lines 7–8.
1. Description

The application defines its Flask secret key directly in the source code:
app = flask.Flask(__name__)app.config["SECRET_KEY"] = "dev-secret-key"



Flask uses this key to sign session cookies.

2. Attacker-controlled input and data flow

An attacker who obtains the source code, or otherwise discovers the secret key, can potentially generate valid Flask session cookies.

The application stores security-relevant information in the session:
flask.session["user"] = user.usernameflask.session["role"] = user.roleflask.session["student_id"] = user.student_idflask.session["courses"] = user.courses or []



An attacker with knowledge of the signing key could potentially construct a modified session containing another username or role.

3. Missing security control and root cause

The secret key is static, predictable and embedded in the application source.

There is no evidence of environment-specific secret management or secure key provisioning.

4. Preconditions and potential impact

Preconditions:
- The application is deployed with this configuration.
- An attacker obtains the secret key.
Potential impacts:
- Forgery of valid session cookies.
- Impersonation of application users.
- Manipulation of session attributes.
An important qualification: session forgery does not automatically imply complete privilege escalation. The actual impact depends on which endpoints trust session attributes and how those attributes are used.

5. Proposed test

Inspect the application's configuration and verify the key used in the running environment.

If the deployment uses this key, attempt to construct a valid session cookie with modified session values and determine whether Flask accepts it.

6. Assumptions and confidence

The hardcoded key is directly demonstrated.

The consequences depend on deployment configuration and session usage.

Confidence: High.

SEC-05 — Hardcoded plaintext user credentials

High
 High confidence

Affected location:
- USERS dictionary.
- Lines 36–43.
1. Description

The application stores usernames and passwords directly in source code:
USERS = {    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),    "prof_srs": User(        username="prof_srs", password="profpw", role="professor", courses=["SRS"]    ),    "admin1": User(username="admin1", password="adminpw", role="admin"),}



Passwords are stored in plaintext rather than using a password hashing mechanism.

2. Attacker-controlled input and data flow

The login endpoint accepts credentials through form parameters:
username = flask.request.form.get("username", "")password = flask.request.form.get("password", "")



The credentials are compared directly:
user = USERS.get(username)if user is None or user.password != password:    return {"error": "invalid credentials"}, 401



An attacker who obtains the source code can retrieve all configured passwords.

3. Missing security control and root cause

The application lacks secure credential storage.

Passwords should not be recoverable directly from application source or a database. A suitable password-hashing mechanism is absent.

4. Preconditions and potential impact

Precondition: Access to the source code or another disclosure mechanism exposing the credentials.

Potential impacts:
- Unauthorized access to existing accounts.
- Administrator or professor impersonation.
- Credential reuse attacks if these passwords are also used elsewhere.
5. Proposed test

Inspect the user storage mechanism and verify whether passwords are stored as plaintext.

Attempt authentication using the credentials present in the source.

6. Assumptions and confidence

Plaintext storage and the configured credentials are directly demonstrated.

Whether these credentials are intended exclusively for a local demonstration or are used in production is unknown.

Confidence: High.

SEC-06 — Missing CSRF protection

Medium
 Medium confidence

Affected locations:
- login() — Lines 82–96.
- logout() — Lines 98–101.
- update_grade() — Lines 128–142.
1. Description

The application uses Flask session cookies for authentication but does not implement any visible Cross-Site Request Forgery (CSRF) protection.

The endpoints accept state-changing HTTP requests without checking CSRF tokens or another explicit request-origin validation mechanism.

2. Attacker-controlled input and data flow

An attacker could potentially create a malicious webpage that causes an authenticated victim's browser to submit a request to the application.

The most significant example is /grades/update.

If the victim has an active session and the browser automatically attaches the session cookie, a malicious cross-origin request may execute with the victim's privileges.

3. Missing security control and root cause

No CSRF tokens, origin validation or equivalent protection are visible in the source.

The root cause is the absence of an explicit CSRF defence for cookie-authenticated state-changing endpoints.

4. Preconditions and potential impact

Preconditions:
- The victim is authenticated.
- The browser sends the session cookie with the cross-origin request.
- The endpoint accepts the request.
Potential impacts:
- Unauthorized actions performed through the victim's session.
- Unauthorized grade modifications if the victim has sufficient privileges in the application.
5. Proposed test

Authenticate in a browser and create a separate page hosted on another origin.

Attempt to trigger a POST request to /grades/update without supplying any CSRF token.

Check whether the browser sends the session cookie and whether the server accepts the request.

6. Assumptions and confidence

The absence of explicit CSRF protection is demonstrated.

Actual exploitability depends on browser cookie settings, deployment configuration and cross-origin request behaviour.

Flask's default session cookie configuration generally uses HttpOnly, but that does not itself prevent CSRF.

Confidence: Medium.

SEC-07 — Flask debug mode enabled

Critical
 High confidence

Affected location:
- Application startup.
- Lines 158–159.
1. Description

The application starts with Flask debug mode enabled:
if __name__ == "__main__":    app.run(debug=True, host="0.0.0.0", port=5001)



The application also listens on 0.0.0.0, making it available on all network interfaces.

2. Attacker-controlled input and execution path

An attacker who can access the application over the network may interact with the Flask development server.

If an application exception occurs, the debug environment may expose Flask's interactive debugger.

3. Missing security control and root cause

Debug mode should not be enabled in a production deployment.

The root cause is the use of development-oriented server configuration without an environment-dependent production configuration.

4. Preconditions and potential impact

Preconditions:
- The application is launched through this startup block.
- It is reachable by an attacker.
- The debugger is exposed and exploitable.
Potential impacts include:
- Disclosure of sensitive application information.
- Interactive debugger access.
- Potential remote code execution through an exposed and exploitable debugger.
The presence of debug=True alone does not establish that remote code execution is possible in the target deployment. Debugger accessibility and its security controls must be verified.

5. Proposed test

Start the application using its documented startup configuration.

Verify:
- Whether debug mode is active.
- Whether the debugger is accessible remotely.
- Whether the server exposes interactive debugging functionality following an exception.
6. Assumptions and confidence

The debug configuration and network binding are directly demonstrated.

Remote exploitability depends on the actual runtime configuration and network exposure.

Confidence: High.

SEC-08 — Sensitive exception information disclosure

Medium
 High confidence

Affected location:
- Function: handle_error()
- Lines: 150–155.
1. Description

The application defines a global exception handler:
@app.errorhandler(Exception)def handle_error(exc):    return {        "error": str(exc),        "type": exc.__class__.__name__,    }, 500



The handler returns the exception message and exception class directly to the HTTP client.

2. Attacker-controlled input and data flow

An attacker can submit malformed or unexpected input that triggers exceptions.

For example:
- Invalid student identifiers.
- Missing JSON fields.
- Invalid JSON bodies.
- Invalid filesystem paths.
The resulting exception is passed to handle_error() and its message is returned to the requester.

3. Missing security control and root cause

There is no separation between internal diagnostic information and externally visible error messages.

The application exposes internal exception details instead of returning generic error responses.

4. Preconditions and potential impact

Precondition: An attacker can trigger an unhandled exception.

Potential impacts:
- Disclosure of filesystem paths.
- Disclosure of internal implementation details.
- Identification of application components and failure conditions.
- Assistance in developing further attacks.
5. Proposed test

Submit a request such as:
GET /students/invalid/profile


Observe whether the response contains the exception message and class.

Repeat with malformed JSON submitted to /grades/update.

6. Assumptions and confidence

The disclosure behaviour is directly demonstrated.

The sensitivity of the disclosed information depends on the exception and deployment environment.

Confidence: High.

SEC-09 — Insufficient input validation

Medium
 High confidence

Affected locations:
- get_profile() — Line 117.
- get_grades() — Line 124.
- update_grade() — Lines 130–142.
1. Description

The application accepts user-controlled input without sufficient validation of types, formats or permitted values.

Examples include:
profile = STUDENT_PROFILES.get(int(student_id))



sid = int(student_id)



And:
student_id = data["student_id"]course_id = data["course_id"]grade = data["grade"]



The application does not validate the grade range, course identifier, student identifier type or the JSON structure beyond accessing individual keys.

2. Attacker-controlled input and data flow

An attacker can submit:
- Non-numeric student identifiers.
- Missing JSON parameters.
- Unexpected data types.
- Negative or excessively large grade values.
- Arbitrary course identifiers.
- Unexpected combinations of student and course identifiers.
These values are used directly in conversions, lookups and modifications.

3. Missing security control and root cause

There is no comprehensive input validation layer.

The application does not enforce a clearly defined schema or business constraints before processing input.

4. Preconditions and potential impact

Precondition: The attacker can access the corresponding endpoints.

Potential impacts:
- Unhandled exceptions and HTTP 500 responses.
- Insertion of invalid academic records.
- Inconsistent application state.
- Potential denial of service through repeated malformed requests.
The impact on academic data integrity overlaps with SEC-01.

5. Proposed test

Submit requests containing:
- "student_id": "invalid"
- "grade": -100
- "grade": "invalid"
- Missing course_id.
- An unexpected JSON structure.
- An unknown course identifier.
Verify whether invalid data is rejected with appropriate client errors or accepted into the application.

6. Assumptions and confidence

The lack of explicit validation is directly demonstrated.

The permitted grade range and course/student validation rules are not defined in the source. Therefore, invalidity of particular values is dependent on the application's intended business requirements.

Confidence: High for missing validation; Medium for the associated business-rule violations.

4. Overall assessment and recommended priorities
Based on the reviewed source, I would prioritize the findings as follows:
Priority 1 — Immediate attention
1. SEC-01: Prevent unauthorized grade modifications.
2. SEC-07: Disable debug mode in production.
3. SEC-03: Restrict file access to the intended directory.
4. SEC-02: Enforce appropriate access controls on student information.

Priority 2 — Authentication and session security
5. SEC-04: Replace the hardcoded Flask secret key.
6. SEC-05: Introduce secure password storage.
7. SEC-06: Implement appropriate CSRF protection.

Priority 3 — Robustness and information disclosure
8. SEC-08: Avoid returning internal exception details.
9. SEC-09: Introduce input validation and business-rule enforcement.

5. Scope limitations and additional observations
A few important considerations when interpreting these results:
- No dynamic verification: None of the proposed attack scenarios was executed. The findings identify weaknesses in the source and plausible exploitation paths, not confirmed attacks against a running deployment.
- Deployment configuration: The review cannot establish whether the application is exposed publicly, whether HTTPS is configured, or whether an external reverse proxy provides additional security controls.
- Authorization policy: The source does not define a complete authorization model. In particular, the expected permissions of students, professors and administrators must be established before classifying every access-control issue against the intended policy.
- External protections: No conclusions can be drawn about protections implemented outside this source, such as network restrictions, WAF rules or infrastructure-level controls.
- Persistence: The application uses in-memory data structures. Consequently, the impact of grade modifications may be limited to the application's running process, depending on deployment and lifecycle behaviour.
Additional observation: The application stores roles, student identifiers and course assignments in session cookies, but the reviewed source does not demonstrate a centralized authorization mechanism that consistently enforces those attributes.

6. Final conclusion
Security posture: Needs improvement
The most concerning issue is the combination of missing authorization checks and exposed data-modification functionality.

In particular, SEC-01 represents a direct integrity risk: the source demonstrates that an HTTP request can reach the grade-modification logic without any authentication or authorization check.

SEC-03 and SEC-07 also deserve immediate attention because they potentially expose the underlying filesystem and application execution environment.

The findings should be treated as a starting point for a more comprehensive security assessment, with particular attention to verifying the application's intended authorization policy and deployment configuration.

Review limitation: This assessment covers only the supplied baseline_secure_coding_api.py file. It does not establish that the application is safe or unsafe in its entirety, and the absence of additional findings should not be interpreted as proof of security.