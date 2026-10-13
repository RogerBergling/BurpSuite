How to install and stuff: https://blog.invid.eu/

This is for BurpSuite. Tested with Community Edition

Problem

Authentication Cookie Synchronization During Security Testing

Background

Modern web applications often use a Backend-for-Frontend (BFF) architecture to manage authentication and user sessions. Authentication is typically maintained through HTTP cookies, which may be automatically refreshed or rotated by the application.

During security testing with tools such as OWASP ZAP and Burp Suite, HTTP requests are captured and replayed to test application functionality and identify vulnerabilities.

The Problem

Security testing tools often replay requests using the original Cookie header captured at the time of interception.

However, when the application automatically refreshes or rotates authentication cookies, the browser receives updated cookie values through Set-Cookie response headers while previously captured requests continue using older values.

This creates a synchronization problem between the browser's active authenticated session and the requests sent by security testing tools.

As a result:

    Replayed requests may contain expired or invalid session cookies.

    Requests may return 401 Unauthorized or 403 Forbidden.

    The application may redirect requests to the login page.

    Authentication-dependent security tests may fail or produce misleading results.

    Testers must manually copy updated cookie values into requests.

    Long-running authenticated testing becomes unreliable.
