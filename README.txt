verify Firebase ID tokens as described in
https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library

* load token signing certificates from a set of URLs
* verify tokens based on the signing certificate ID (key ID) identified in the token
* periodically update certificates
