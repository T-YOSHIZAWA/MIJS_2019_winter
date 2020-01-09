package jp.mijs.winter2019.security.webauthn.repository;

import java.util.List;
import java.util.Optional;

import javax.sql.DataSource;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.namedparam.BeanPropertySqlParameterSource;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.stereotype.Repository;

import jp.mijs.winter2019.security.webauthn.entity.Credential;

/**
 * データベースから公開鍵クレデンシャルを取得・登録するためのクラス
 * @author yoshizawa
 *
 */
@Repository
public class CredentialRepository {
  private final NamedParameterJdbcOperations jdbc;
  private final SimpleJdbcInsert insertCredential;

  /**
   * コンストラクタ。
   * SpringBootによるDIが実行される
   * @param jdbc
   * @param dataSource
   */
  public CredentialRepository(NamedParameterJdbcOperations jdbc, DataSource dataSource) {
    this.jdbc = jdbc;
    this.insertCredential = new SimpleJdbcInsert(dataSource).withTableName("credential");
  }
  
  /**
   * ユーザIDから公開鍵クレデンシャル情報を取得する。
   * @param userId ユーザID
   * @return 取得した公開鍵クレデンシャル情報を格納したListオブジェクト
   */
  public List<Credential> findByUserId(byte[] userId) {
    var sql = 
        "SELECT * " +
        "FROM " +
          "credential " +
        "WHERE " +
          "user_id = :userId";
    return jdbc.query(
        sql,
        new MapSqlParameterSource().addValue("userId", userId),
        new BeanPropertyRowMapper<>(Credential.class)
    );
  }

  /**
   * 公開鍵クレデンシャル情報をIDから取得する。
   * @param credentialId 公開鍵クレデンシャルID
   * @return 公開鍵クレデンシャル情報 - 存在しない場合は Optional.empty
   */
  public Optional<Credential> findById(byte[] credentialId) {
    var sql = 
        "SELECT * " +
          "FROM " +
            "credential " +
          "WHERE " +
            "credential_id = :credentialId";
    try {
      var params = new MapSqlParameterSource()
          .addValue("credentialId", credentialId);

      var credential = jdbc.queryForObject(sql, params, new BeanPropertyRowMapper<>(Credential.class));
      return Optional.of(credential);
    } catch (EmptyResultDataAccessException ignore) {
      return Optional.empty();
    }
  }

  /**
   * 公開鍵クレデンシャル情報をデータベースに登録する。
   * @param credential 公開鍵クレデンシャル情報
   */
  public void insert(Credential credential) {
    insertCredential.execute(new BeanPropertySqlParameterSource(credential));
  }

  /**
   * 公開鍵クレデンシャル情報を更新する。
   * 更新する情報は認証器カウンタのみとする。
   * @param credential 公開鍵クレデンシャル情報
   */
  public void update(Credential credential) {
    var sql = 
        "UPDATE " + 
          "credential " + 
        "SET " + 
          "signature_counter = :signatureCounter " + 
        "WHERE " + 
          "credential_id = :credentialId";
    MapSqlParameterSource params = new MapSqlParameterSource()
        .addValue("credentialId", credential.getCredentialId())
        .addValue("signatureCounter", credential.getSignatureCounter());

    jdbc.update(sql, params);
  }
}
