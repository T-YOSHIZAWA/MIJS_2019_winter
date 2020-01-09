package jp.mijs.winter2019.security.webauthn.entity;

import lombok.Data;
import lombok.ToString;

/**
 * 公開鍵クレデンシャル情報 
 */
@Data
@ToString
public class Credential {
  /** クレデンシャルID */
  private byte[] credentialId;
  /** ユーザID */
  private byte[] userId;
  /** 公開鍵クレデンシャル */
  private byte[] publicKey;
  /** 認証器カウンタ */
  private long signatureCounter;
}
