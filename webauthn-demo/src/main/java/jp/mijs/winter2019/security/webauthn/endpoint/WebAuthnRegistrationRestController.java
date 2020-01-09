package jp.mijs.winter2019.security.webauthn.endpoint;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.client.challenge.Challenge;

import jp.mijs.winter2019.security.webauthn.entity.User;
import jp.mijs.winter2019.security.webauthn.service.WebAuthnRegistrationService;

/**
 * WebAuthnによるユーザ登録のエンドポイント
 */
@RestController
public class WebAuthnRegistrationRestController {
  private final WebAuthnRegistrationService webAuthnService;

  /**
   * コンストラクタ。
   * SpringBootによるDIが実行される。
   * @param webAuthnService
   */
  public WebAuthnRegistrationRestController(WebAuthnRegistrationService webAuthnService) {
    this.webAuthnService = webAuthnService;
  }

  // POST /attestation/options のJSONパラメータ
  private static class AttestationOptionsParam {
    public String email;
    public String displayName;
  }

  // POST /attestation/options のエンドポイント
  @PostMapping(value = "/attestation/options")
  public PublicKeyCredentialCreationOptions postAttestationOptions(
      @RequestBody AttestationOptionsParam params,
      HttpServletRequest httpRequest) {

    var user = webAuthnService.findOrElseCreate(params.email, params.displayName); // ユーザの存在チェック - 存在しない場合はユーザを新規作成
    var options = webAuthnService.creationOptions(user);

    // challengeとユーザ情報をHTTPセッションに一時保存
    var session = httpRequest.getSession();
    session.setAttribute("attestationChallenge", options.getChallenge());
    session.setAttribute("attestationUser", user);

    return options;
  }

  // POST /attestation/result のJSONパラメータ
  private static class AttestationResultParam {
    public byte[] clientDataJSON;
    public byte[] attestationObject;
  }

  // POST /attestation/result のエンドポイント
  @PostMapping(value = "/attestation/result")
  public void postAttestationOptions(@RequestBody AttestationResultParam params, HttpServletRequest httpRequest) {

    // HTTPセッションからchallengeを取得
    var httpSession = httpRequest.getSession();
    var challenge = (Challenge) httpSession.getAttribute("attestationChallenge");
    var user = (User) httpSession.getAttribute("attestationUser");

    // ※サンプルコードでは、HTTPセッションからchallengeを削除
    httpSession.removeAttribute("attestationChallenge");
    httpSession.removeAttribute("attestationUser");

    // 公開鍵クレデンシャルの検証と保存
    webAuthnService.creationFinish(user, challenge, params.clientDataJSON, params.attestationObject);
  }
}
