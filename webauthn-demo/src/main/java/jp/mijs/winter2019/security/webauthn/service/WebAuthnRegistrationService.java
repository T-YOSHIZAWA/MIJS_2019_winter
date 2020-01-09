package jp.mijs.winter2019.security.webauthn.service;

import java.security.SecureRandom;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticatorAttachment;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.webauthn4j.validator.attestation.statement.androidkey.AndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.TPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.NullECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessValidator;

import jp.mijs.winter2019.security.webauthn.entity.Credential;
import jp.mijs.winter2019.security.webauthn.entity.User;
import jp.mijs.winter2019.security.webauthn.repository.CredentialRepository;
import jp.mijs.winter2019.security.webauthn.repository.UserRepository;

/**
 * WebAuthnによるユーザの登録を行うサービス
 */
@Service
public class WebAuthnRegistrationService {
  private static final String DOMAIN_NAME = "localhost";
  
  private final UserRepository userRepository;
  private final CredentialRepository credentialRepository;

  /**
   * コンストラクタ。
   * SpringBootによるDIが実行される
   * @param userRepository
   * @param credentialRepository
   */
  public WebAuthnRegistrationService(UserRepository userRepository, CredentialRepository credentialRepository) {
      this.userRepository = userRepository;
      this.credentialRepository = credentialRepository;
  }

  /**
   * 登録要求に対するレスポンスを生成する。
   * レスポンスの内容はWebAuthnの仕様に従う。
   * @param user ユーザ情報
   * @return 登録要求に対するレスポンス
   */
  public PublicKeyCredentialCreationOptions creationOptions(User user) {

    //rp - RP(認証局)情報 - 中間者攻撃への耐性
    var rpId = DOMAIN_NAME;
    var rpName = "MIJS 2019Winter Security";
    var rp = new PublicKeyCredentialRpEntity(rpId, rpName);

    //user - ユーザ情報
    var userId = user.getId();
    var userName = user.getEmail();
    var userDisplayName = user.getDisplayName();
    var userInfo = new PublicKeyCredentialUserEntity(
            userId,
            userName,
            userDisplayName);
    
    //challenge - リプレイ攻撃への耐性
    var challenge = new DefaultChallenge();

    //pubKeyCredParams - 公開鍵クレデンシャルの生成方法の要求事項
    // アルゴリズムについてはこちらを参照(https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
    // 先に定義したものほど優先して使用される(この場合はES256を優先する)
    var es256 = new PublicKeyCredentialParameters(
            PublicKeyCredentialType.PUBLIC_KEY,
            COSEAlgorithmIdentifier.ES256);
    var rs256 = new PublicKeyCredentialParameters(
            PublicKeyCredentialType.PUBLIC_KEY,
            COSEAlgorithmIdentifier.RS256);
    var pubKeyCredParams = List.of(es256, rs256);

    //timeout - 登録のタイムアウト時間（ミリ秒）
    var timeout = 120000L;

    //excludeCredentials ─ 同一認証器の登録制限
    //  Userに紐付いたクレデンシャルIDを設定することで、同一の認証器の複数登録を制限する
    var credentials = credentialRepository.findByUserId(user.getId());
    var excludeCredentials = credentials.stream()
        .map(credential -> new PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            credential.getCredentialId(),
            Set.of()))
        .collect(Collectors.toList());

    //authenticatorSelection ─ 認証器の要求事項
    //  認証器を指定
    AuthenticatorAttachment authenticatorAttachment = 
        //AuthenticatorAttachment.CROSS_PLATFORM; //プラットフォーム外部の認証器(USB,Bluetooth など)
        //AuthenticatorAttachment.PLATFORM;   //プラットフォームの認証器を使用(指紋認証,PIN認証 など)
        null;   //認証器を固定しない
    //認証器でレジデントクレデンシャルを保管するかを設定
    var requireResidentKey = false;
    //認証器での個別ユーザ検証(生体認証やPIN認証 など)を行うか
    var userVerificationRequirement = 
        //UserVerificationRequirement.REQUIRED;       //検証を必須とする
        //UserVerificationRequirement.DISCOURAGED;    //検証しない
        UserVerificationRequirement.PREFERRED;      //任意(認証機に機能があれば使用する そうでなければ使用しない)
    var authenticatorSelection = new AuthenticatorSelectionCriteria(
        authenticatorAttachment,
        requireResidentKey,
        userVerificationRequirement
    );

    //attestation ─ 認証器の信頼性に関する情報(アテステーションステートメント)の要求
    var attestation =
        //AttestationConveyancePreference.DIRECT; //要求する
        //AttestationConveyancePreference.NONE;   //要求しない
        AttestationConveyancePreference.INDIRECT;   //クライアントの判断

    // 公開鍵クレデンシャル生成API（navigator.credentials.create）のパラメータを作成
    return new PublicKeyCredentialCreationOptions(
            rp,
            userInfo,
            challenge,
            pubKeyCredParams,
            timeout,
            excludeCredentials,
            authenticatorSelection,
            attestation,
            null    //拡張機能を使用する場合は、ここで宣言 - AuthenticationExtensionsClientInputs<> オブジェクト
    );
  }

  /**
   * メールアドレスからユーザ情報を検索する。
   * ユーザ情報が存在しない場合は新規に作成する。
   * @param email メールアドレス
   * @param displayName 表示名称
   * @return ユーザ情報
   */
  public User findOrElseCreate(String email, String displayName) {
    return userRepository.findByEmail(email)
        .orElseGet(() -> createUser(email, displayName));
  }

  /**
   * ユーザ情報を新規に作成する。
   * @param email メールアドレス
   * @param displayName 表示名称
   * @return 新規作成されたユーザ情報
   */
  private User createUser(String email, String displayName) {
    // 個人が特定できない最大64バイトのランダムなバイト列
    var userId = new byte[32];
    new SecureRandom().nextBytes(userId);

    var user = new User();
    user.setId(userId);
    user.setEmail(email);
    user.setDisplayName(displayName);
    return user;
  }

  /**
   * 認証情報をサーバ上に登録する。
   * クライアントから送信された情報の検証を行い、問題がなければサーバ上に公開鍵を登録する。
   * @param user ユーザ情報
   * @param challenge サーバで保持するチャレンジ情報
   * @param clientDataJSON クライアントから送信されたクレデンシャル生成のデータ
   * @param attestationObject クライアントから送信された公開鍵情報
   */
  public void creationFinish(User user, Challenge challenge, byte[] clientDataJSON, byte[] attestationObject) {
    //検証用サーバ情報を生成
    var serverProperty = new ServerProperty(
        Origin.create(String.format("https://%s:8443", DOMAIN_NAME)), // Originの検証 - サーバが保持している値を設定
        DOMAIN_NAME,    //rpIdの検証 - サーバが保持している値を設定
        challenge,      //challengeの検証 - HTTPセッションに格納された値を設定
        null            //TokenBindingId - 特に指定がなければNULLを設定
    );

    //flagsの検証 ─ ユーザ検証（多要素認証）
    //var userVerificationRequired = true; //多要素認証を行っている
    var userVerificationRequired = false;   //多要素認証を行っていない

    //検証データを生成
    var registrationContext = new WebAuthnRegistrationContext(
        clientDataJSON,     //クレデンシャルの生成に使用されたデータ
        attestationObject,  //認証器が生成した公開鍵や認証器の正当性を証明するための証明書
        serverProperty,     //中間攻撃やリプレイ攻撃を防ぐための検証用サーバ情報
        userVerificationRequired    //多要素認証チェック
    );

    //認証デバイスの厳密な検証を行う場合のValidator
    var validator = new WebAuthnRegistrationContextValidator(
        //アテステーション・ステートメントのフォーマットは全部で6種類
        List.of(
            // https://www.w3.org/TR/webauthn-1/#packed-attestation
            new PackedAttestationStatementValidator(),
            // https://www.w3.org/TR/webauthn-1/#tpm-attestation
            new TPMAttestationStatementValidator(),
            // https://www.w3.org/TR/webauthn-1/#android-key-attestation
            new AndroidKeyAttestationStatementValidator(),
            // https://www.w3.org/TR/webauthn-1/#android-safetynet-attestation
            new AndroidSafetyNetAttestationStatementValidator(),
            // https://www.w3.org/TR/webauthn-1/#fido-u2f-attestation
            new FIDOU2FAttestationStatementValidator(),
            // https://www.w3.org/TR/webauthn-1/#none-attestation
            new NoneAttestationStatementValidator()),
        new NullCertPathTrustworthinessValidator(), new NullECDAATrustworthinessValidator(),
        new DefaultSelfAttestationTrustworthinessValidator());

    //Validatorを使用して認証情報の検証実行
    var response = validator.validate(registrationContext);

    // DBに保存する公開鍵クレデンシャルを取得
    var credentialId = response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData()
        .getCredentialId();

    //公開鍵クレデンシャルを生成
    //  公開鍵クレデンシャルの他にアテステーションステートメントを含める
    var authenticator = new OriginalAuthenticator(
        response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
        response.getAttestationObject().getAttestationStatement(),
        response.getAttestationObject().getAuthenticatorData().getSignCount());

    var signatureCounter = response.getAttestationObject().getAuthenticatorData().getSignCount();

    // ユーザ作成
    if (userRepository.findByEmail(user.getEmail()).isEmpty()) {
      userRepository.insert(user);
    }

    // 公開鍵クレデンシャルの保存
    var credential = new Credential();
    credential.setCredentialId(credentialId);
    credential.setUserId(user.getId());
    credential.setPublicKey(new CborConverter().writeValueAsBytes(authenticator));
    credential.setSignatureCounter(signatureCounter);
    credentialRepository.insert(credential);
  }
}
