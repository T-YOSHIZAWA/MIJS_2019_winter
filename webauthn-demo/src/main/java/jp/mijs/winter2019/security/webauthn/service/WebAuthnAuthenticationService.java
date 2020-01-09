package jp.mijs.winter2019.security.webauthn.service;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;

import jp.mijs.winter2019.security.webauthn.entity.User;
import jp.mijs.winter2019.security.webauthn.repository.CredentialRepository;
import jp.mijs.winter2019.security.webauthn.repository.UserRepository;

@Service
public class WebAuthnAuthenticationService {
  private static final String DOMAIN_NAME = "localhost";
  
  private final UserRepository userRepository;
  private final CredentialRepository credentialRepository;

  /**
   * コンストラクタ。
   * SpringBootによるDIが実行される
   * @param userRepository
   * @param credentialRepository
   */
  public WebAuthnAuthenticationService(UserRepository userRepository, CredentialRepository credentialRepository) {
      this.userRepository = userRepository;
      this.credentialRepository = credentialRepository;
  }

  public Optional<User> find(String email) {
    return userRepository.findByEmail(email);
  }
  
  public PublicKeyCredentialRequestOptions requestOptions(User user) {
    //challenge - リプレイ攻撃への耐性
    var challenge = new DefaultChallenge();

    //timeout - 登録のタイムアウト時間（ミリ秒）
    var timeout = 120000L;

    //rp - RP(認証局)情報 - 中間者攻撃への耐性
    var rpId = DOMAIN_NAME;

    // allowCredentials ── RPサーバに登録されたクレデンシャルIDの一覧
    List<PublicKeyCredentialDescriptor> allowCredentials = List.of();
    if (user != null) {
      var credentials = credentialRepository.findByUserId(user.getId());
      allowCredentials = credentials.stream()
          .map(credential -> new PublicKeyCredentialDescriptor(
              PublicKeyCredentialType.PUBLIC_KEY,
              credential.getCredentialId(),
              Set.of()))
          .collect(Collectors.toList());
    }

    //認証器での個別ユーザ検証(生体認証やPIN認証 など)を行うか
    var userVerificationRequirement = 
        //UserVerificationRequirement.REQUIRED;       //検証を必須とする
        //UserVerificationRequirement.DISCOURAGED;    //検証しない
        UserVerificationRequirement.PREFERRED;      //任意(認証機に機能があれば使用する そうでなければ使用しない)

    //公開鍵クレデンシャル要求API（navigator.credentials.get）のパラメータを作成
    return new PublicKeyCredentialRequestOptions(
        challenge,
        timeout,
        rpId,
        allowCredentials,
        userVerificationRequirement,
        null //拡張機能を使用する場合は、ここで宣言 - AuthenticationExtensionsClientInputs<>オブジェクト
    );
  }

  public void assertionFinish(Challenge challenge, 
                              byte[] credentialId,
                              byte[] clientDataJSON,
                              byte[] authenticatorData,
                              byte[] signature) {

    //検証用サーバ情報を生成
    var serverProperty = new ServerProperty(
        Origin.create(String.format("https://%s:8443", DOMAIN_NAME)), // Originの検証 - サーバが保持している値を設定
        DOMAIN_NAME,    //rpIdの検証 - サーバが保持している値を設定
        challenge,      //challengeの検証 - HTTPセッションに格納された値を設定
        null            //TokenBindingId - 特に指定がなければNULLを設定
    );

    //flagsの検証 ── ユーザ検証（多要素認証）
    //var userVerificationRequired = true;
    var userVerificationRequired = false;

    // 検証データを生成
    var authenticationContext = new WebAuthnAuthenticationContext(
        credentialId,       //認証器から取得したクレデンシャルID
        clientDataJSON,     //クレデンシャルの生成に使用されたデータ
        authenticatorData,  //認証器から取得した公開鍵クレデンシャルのデータ
        signature,          //認証器の秘密鍵による署名データ - 公開鍵で検証を行う
        serverProperty,     //中間攻撃やリプレイ攻撃を防ぐための検証用サーバ情報
        userVerificationRequired    //多要素認証チェック
    );

    //DBから登録済みの公開鍵クレデンシャルを取得
    var credential = credentialRepository.findById(credentialId).orElseThrow();

    //公開鍵クレデンシャルをバイナリからデシリアライズ
    OriginalAuthenticator authenticator = new CborConverter().readValue(credential.getPublicKey(),
        OriginalAuthenticator.class);

    //Validatorの生成
    var validator = new WebAuthnAuthenticationContextValidator();

    //Validatorを使用して検証データと公開鍵クレデンシャルを検証
    //  clientDataJSONの検証 ─ 認証情報の生成に渡されたデータ
    //  signatureの検証 ─ 公開鍵による署名の検証
    //  signCountの検証 ─ クローン認証器の検出
    var response = validator.validate(authenticationContext, authenticator);

    //署名カウンタの更新
    var currentCounter = response.getAuthenticatorData().getSignCount();
    credential.setSignatureCounter(currentCounter);
    credentialRepository.update(credential);
  }
}
