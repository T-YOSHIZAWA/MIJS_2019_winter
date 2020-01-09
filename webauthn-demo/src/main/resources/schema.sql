DROP TABLE IF EXISTS credential;
DROP TABLE IF EXISTS user;

-- ユーザを保管するテーブル
CREATE TABLE user
(
    id           VARBINARY(64) NOT NULL PRIMARY KEY,
    email        VARCHAR(250)  NOT NULL UNIQUE,
    display_name VARCHAR(255)  NOT NULL
);

-- 公開鍵クレデンシャルを保管するテーブル
CREATE TABLE credential
(
    credential_id     VARBINARY(255) NOT NULL PRIMARY KEY,
    user_id           VARBINARY(64)  NOT NULL,
    public_key        BLOB           NOT NULL,
    signature_counter LONG           NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user (id)
);
