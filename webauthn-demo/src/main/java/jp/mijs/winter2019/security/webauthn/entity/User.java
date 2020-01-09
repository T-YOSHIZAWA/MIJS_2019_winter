package jp.mijs.winter2019.security.webauthn.entity;

import lombok.Data;

/**
 * ユーザ情報
 */
@Data
public class User {
  /** ユーザID */
  private byte[] id;
  /** メールアドレス(ログインIDに使用) */
  private String email;
  /** 表示名称 */
  private String displayName;
}
