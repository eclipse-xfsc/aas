## Initial keycloak setup


Keycloak (https://www.keycloak.org/) was chosen as an IAM Platform for our service deployment. Our service and test application to be protected must be registered with IAM solution properly. To setup keycloak platform the following steps must be accomplished:

- download keycloak image from the Keycloak site
- unzip downloaded archive to ${KC_HOME}
- start keycloak application using ${KC_HOME}/bin/standalone script
- open keycloak Admin console in your browser at http://localhost:8080/auth
- at first login create new user with login and password
- ![Keycloak Admin console](./images/image2022-2-7_15-19-20.png "Keycloak Admin console")
- on the next screen hit the Administration Console link and login to it with just created credentials
- move mouse pointer to the top-left corner under the Master realm and hit the appeared Add realm button:
- ![Keycloak Admin console](./images/image2022-2-7_15-23-15.png "Keycloak Admin console")
- set gaia-x name for the new realm and hit Create button
- ![Keycloak Admin console](./images/image2022-2-7_15-27-28.png "Keycloak Admin console")
- now go to the Client Registration tab in the realm settings and press Create button in the top-right corner:
- ![Keycloak Admin console](./images/image2022-2-7_15-46-41.png "Keycloak Admin console")
- set Count to 1000000 and hit Save button, then copy and store the generated IAT
- the generated IAT will be used later in the IAT Provider scenarios
