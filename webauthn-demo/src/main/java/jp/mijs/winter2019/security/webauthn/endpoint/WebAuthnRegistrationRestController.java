package jp.mijs.winter2019.security.webauthn.endpoint;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.client.challenge.Challenge;

import jp.mijs.winter2019.security.webauthn.entity.User;
import jp.mijs.winter2019.security.webauthn.service.WebAuthnRegistrationService;
import lombok.extern.slf4j.Slf4j;

/**
 * WebAuthnによる登録のエンドポイント
 */
@RestController
@Slf4j
public class WebAuthnRegistrationRestController {
  private final WebAuthnRegistrationService webAuthnService;
  private final ObjectMapper objectMapper;
  /**
   * コンストラクタ。
   * SpringBootによるDIが実行される。
   * @param webAuthnService
   */
  public WebAuthnRegistrationRestController(WebAuthnRegistrationService webAuthnService, ObjectMapper objectMapper) {
    this.webAuthnService = webAuthnService;
    this.objectMapper = objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
  }

  /**
   * 登録要求に対するエンドポイント。
   * URL: /attestation/options
   * @param params リクエストパラメータ
   * @param httpRequest HTTPリクエスト情報
   * @return 登録要求に対するレスポンス情報
   * @throws JsonProcessingException JSON変換に失敗した場合はこの例外をスローする
   */
  @PostMapping(value = "/attestation/options")
  public PublicKeyCredentialCreationOptions postAttestationOptions(
      @RequestBody AttestationOptionsParam params,
      HttpServletRequest httpRequest) throws JsonProcessingException {
    log.info("/attestation/options...");
    
    var user = webAuthnService.findOrElseCreate(params.email, params.displayName); // ユーザの存在チェック - 存在しない場合はユーザを新規作成
    var options = webAuthnService.creationOptions(user);

    // challengeとユーザ情報をHTTPセッションに一時保存
    var session = httpRequest.getSession();
    session.setAttribute("attestationChallenge", options.getChallenge());
    session.setAttribute("attestationUser", user);
    log.debug("USER: {}", user);
    log.debug("Challenge: {}", options.getChallenge().getValue());
    log.debug("Response Data\n{}", this.objectMapper.writeValueAsString(options));

    return options;
  }
  // POST /attestation/options のJSONパラメータ
  private static class AttestationOptionsParam {
    public String email;
    public String displayName;
  }

  /**
   * 登録に対するエンドポイント
   * @param params リクエストパラメータ
   * @param httpRequest HTTPリクエスト情報
   */
  @PostMapping(value = "/attestation/result")
  public void postAttestationOptions(@RequestBody AttestationResultParam params, HttpServletRequest httpRequest) {
    log.info("/attestation/result...");

    // HTTPセッションからUserとChallengeを取得
    var httpSession = httpRequest.getSession();
    var challenge = (Challenge) httpSession.getAttribute("attestationChallenge");
    var user = (User) httpSession.getAttribute("attestationUser");
    log.debug("USER: {}", user);
    log.debug("Challenge: {}", challenge.getValue());
    
    // UserとChallengeをセッションから削除することで、リプレイ攻撃を防ぐ
    httpSession.removeAttribute("attestationChallenge");
    httpSession.removeAttribute("attestationUser");

    // 公開鍵クレデンシャルの検証と保存
    webAuthnService.creationFinish(user, challenge, params.clientDataJSON, params.attestationObject);
  }
  // POST /attestation/result のJSONパラメータ
  private static class AttestationResultParam {
    public byte[] clientDataJSON;
    public byte[] attestationObject;
  }
}
