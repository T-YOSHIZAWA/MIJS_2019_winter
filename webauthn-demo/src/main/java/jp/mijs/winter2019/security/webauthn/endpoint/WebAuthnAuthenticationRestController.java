package jp.mijs.winter2019.security.webauthn.endpoint;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.client.challenge.Challenge;

import jp.mijs.winter2019.security.webauthn.service.WebAuthnAuthenticationService;

@RestController
public class WebAuthnAuthenticationRestController {
  private final WebAuthnAuthenticationService webAuthnService;

  public WebAuthnAuthenticationRestController(WebAuthnAuthenticationService webAuthnService) {
    this.webAuthnService = webAuthnService;
  }

  // POST /assertion/options のJSONパラメータ
  private static class AssertionOptionsParam {
    public String email;
  }

  // POST /assertion/options のエンドポイントを設定
  @PostMapping(value = "/assertion/options")
  public PublicKeyCredentialRequestOptions postAssertionOptions(
      @RequestBody AssertionOptionsParam params,
      HttpServletRequest httpRequest) {

    var user = webAuthnService.find(params.email).orElse(null);
    var options = webAuthnService.requestOptions(user);

    // challengeをHTTPセッションに一時保存
    var session = httpRequest.getSession();
    session.setAttribute("assertionChallenge", options.getChallenge());

    return options;
  }


  // POST /assertion/result のJSONパラメータ
  private static class AuthenticationResultParam {
    public byte[] credentialId;
    public byte[] clientDataJSON;
    public byte[] authenticatorData;
    public byte[] signature;
    public byte[] userHandle;
  }

  // POST /assertion/result のエンドポイント
  @PostMapping(value = "/assertion/result")
  public void postAssertionResult(@RequestBody AuthenticationResultParam params, HttpServletRequest httpRequest) {

    // HTTPセッションからchallengeを取得
    var httpSession = httpRequest.getSession();
    var challenge = (Challenge) httpSession.getAttribute("assertionChallenge");

    // ※サンプルコードでは、HTTPセッションからchallengeを削除
    httpSession.removeAttribute("assertionChallenge");

    // 署名の検証
    webAuthnService.assertionFinish(
        challenge,
        params.credentialId,
        params.clientDataJSON,
        params.authenticatorData,
        params.signature);
  }
}
