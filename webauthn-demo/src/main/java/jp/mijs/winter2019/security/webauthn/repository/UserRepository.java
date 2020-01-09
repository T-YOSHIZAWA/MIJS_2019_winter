package jp.mijs.winter2019.security.webauthn.repository;

import java.util.Optional;

import javax.sql.DataSource;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.namedparam.BeanPropertySqlParameterSource;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.simple.SimpleJdbcInsert;
import org.springframework.stereotype.Repository;

import jp.mijs.winter2019.security.webauthn.entity.User;

/**
 * データベースからユーザ情報を取得・登録するためのクラス
 * @author yoshizawa
 *
 */
@Repository
public class UserRepository {
  private final NamedParameterJdbcOperations jdbc;
  private final SimpleJdbcInsert insertUser;

  /**
   * コンストラクタ。
   * SpringBootによるDIが実行される。
   * @param jdbc
   * @param dataSource
   */
  public UserRepository(NamedParameterJdbcOperations jdbc, DataSource dataSource) {
    this.jdbc = jdbc;
    this.insertUser = new SimpleJdbcInsert(dataSource).withTableName("user");
  }

  /**
   * メールアドレスからユーザ情報を取得する。
   * @param email メールアドレス
   * @return ユーザ情報 - 存在しない場合は Optional.empty
   */
  public Optional<User> findByEmail(String email) {
    var sql = 
        "SELECT * " +
        "FROM " +
          "user " +
        "WHERE " +
          "email=:email";
    try {
      var params = new MapSqlParameterSource()
          .addValue("email", email);
      var user = jdbc.queryForObject(sql, params, new BeanPropertyRowMapper<>(User.class));
      return Optional.of(user);
    } catch (EmptyResultDataAccessException ignore) {
      return Optional.empty();
    }
  }

  /**
   * ユーザ情報をデータベースに登録する。
   * @param user ユーザ情報
   */
  public void insert(User user) {
    insertUser.execute(new BeanPropertySqlParameterSource(user));
  }
}
