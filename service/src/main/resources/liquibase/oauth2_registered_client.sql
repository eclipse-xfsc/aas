--liquibase formatted sql
--changeset admin:create_oauth2_registered_client
CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamp DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods text NOT NULL,
    authorization_grant_types text NOT NULL,
    redirect_uris text DEFAULT NULL,
    scopes text NOT NULL,
    client_settings text NOT NULL,
    token_settings text NOT NULL,
    PRIMARY KEY (id)
);
--rollback DROP TABLE oauth2_registered_client

--changeset admin:init_oauth2_registered_client
INSERT INTO oauth2_registered_client(id, client_id, client_id_issued_at, client_secret, client_secret_expires_at, client_name, client_authentication_methods, 
    authorization_grant_types, redirect_uris, scopes, client_settings, token_settings) 
VALUES 
    ('9a9135be-5923-4d96-aefe-bf275ef14087', 'aas-app-oidc', '2023-04-19 01:32:00.866534', '{noop}secret', null, 'SSI OIDC Keycloak Client', 'client_secret_basic,client_secret_post', 
     'client_credentials,authorization_code,refresh_token', 'http://key-server:8080/realms/gaia-x/broker/ssi-oidc/endpoint,https://key-server.gxfs.dev/realms/gaia-x/broker/ssi-oidc/endpoint', 'openid,profile,email', 
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-authorization-consent":false,"settings.client.token-endpoint-authentication-signing-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","PS256"],"settings.client.require-proof-key":false,"ssi_auth_type":"OIDC"}', 
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}'),
    ('3e61c3f2-f11a-41d8-bf67-a96fce63a37b', 'aas-app-siop', '2023-04-19 01:49:55.362801', '{noop}secret2', null, 'SSI SIOP Keycloak Client', 'client_secret_basic', 
     'client_credentials,authorization_code,jwt_bearer', 'http://key-server:8080/realms/gaia-x/broker/ssi-siop/endpoint,https://key-server.gxfs.dev/realms/gaia-x/broker/ssi-siop/endpoint', 'openid,profile,email', 
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-authorization-consent":false,"settings.client.token-endpoint-authentication-signing-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.client.require-proof-key":false,"ssi_auth_type":"SIOP"}', 
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}'),
    ('aa23609d-7be4-4686-9a25-3d6dc75e888f', 'gxfs-demo', '2023-04-19 01:49:55.41815', null, null, 'GXFS Integration Portal Client', 'none', 
     'client_credentials,authorization_code', 'https://demo.gxfs.dev,http://integration.gxfs.dev', 'openid,profile,email', 
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-authorization-consent":false,"settings.client.token-endpoint-authentication-signing-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","ES256"],"settings.client.require-proof-key":false}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}'),
    ('19f5b898-b245-4f32-b989-686dd41e665e', 'demo-portal', '2023-04-19 01:49:55.472173', '{noop}demo-portal', null, 'FC Demo Portal Client', 'client_secret_basic,client_secret_post', 
     'authorization_code,client_credentials,jwt_bearer,refresh_token', 'https://fc-demo-server.gxfs.dev,https://fc-server.gxfs.dev,http://78.138.66.181:8088/*', 'openid,profile,email', 
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-authorization-consent":false,"settings.client.token-endpoint-authentication-signing-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.client.require-proof-key":false}',
     '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000]}');
--rollback DELETE FROM oauth2_registered_client

--changeset admin:alter_oauth2_registered_client_add_post_logout_column
ALTER TABLE oauth2_registered_client ADD COLUMN IF NOT EXISTS post_logout_redirect_uris text DEFAULT NULL;
--rollback ALTER TABLE oauth2_registered_client DROP COLUMN IF EXISTS post_logout_redirect_uris

--changeset admin:update_oauth2_registered_client_secret
UPDATE oauth2_registered_client SET client_secret = '{bcrypt}$2a$10$a5sIL2CKZ6qmlDdPFzLNNef42A6PeQVYaVNcuhFVdl8Bk6dlUkKsy' WHERE id = '9a9135be-5923-4d96-aefe-bf275ef14087';
UPDATE oauth2_registered_client SET client_secret = '{bcrypt}$2a$10$jP1vlT5g0EZhy/ibgrrOw.dbkWjnyrPmqVYAqXEodJ8D0uUqpv81u' WHERE id = '3e61c3f2-f11a-41d8-bf67-a96fce63a37b';
UPDATE oauth2_registered_client SET client_secret = '{bcrypt}$2a$10$EaRGe7d5DIr.46h/IX2m0ezTxlbr4/XVmZ6sp9nitJR6PDQs6.7My' WHERE id = '19f5b898-b245-4f32-b989-686dd41e665e';
