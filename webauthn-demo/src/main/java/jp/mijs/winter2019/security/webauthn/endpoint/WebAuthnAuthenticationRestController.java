package jp.mijs.winter2019.security.webauthn.endpoint;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.client.challenge.Challenge;

import jp.mijs.winter2019.security.webauthn.service.WebAuthnAuthenticationService;
import lombok.extern.slf4j.Slf4j;

/**
 * WebAuthnによる認証のエンドポイント
 */
@RestController
@Slf4j
public class WebAuthnAuthenticationRestController {
  private final WebAuthnAuthenticationService webAuthnService;
  private final ObjectMapper objectMapper;

  public WebAuthnAuthenticationRestController(WebAuthnAuthenticationService webAuthnService, ObjectMapper objectMapper) {
    this.webAuthnService = webAuthnService;
    this.objectMapper = objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
  }

  /**
   * 認証要求に対するエンドポイント。
   * URL: /assertion/options
   * @param params リクエストパラメータ
   * @param httpRequest HTTPリクエスト情報
   * @return 認証要求に対するレスポンス情報
   * @throws JsonProcessingException JSON変換に失敗した場合はこの例外をスローする
   */
  @PostMapping(value = "/assertion/options")
  public PublicKeyCredentialRequestOptions postAssertionOptions(
      @RequestBody AssertionOptionsParam params,
      HttpServletRequest httpRequest) throws JsonProcessingException {
    log.info("/assertion/options...");
    
    var user = webAuthnService.find(params.email).orElse(null);
    var options = webAuthnService.requestOptions(user);

    // challengeをHTTPセッションに一時保存
    var session = httpRequest.getSession();
    session.setAttribute("assertionChallenge", options.getChallenge());
    log.debug("Challenge: {}", options.getChallenge().getValue());
    log.debug("Response Data:\n{}", this.objectMapper.writeValueAsString(options));
    
    return options;
  }
  // POST /assertion/options のJSONパラメータ
  private static class AssertionOptionsParam {
    public String email;
  }

  /**
   * 認証に対するエンドポイント。
   * URL: /assertion/result
   * @param params リクエストパラメータ
   * @param httpRequest HTTPリクエスト情報
   */
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
  // POST /assertion/result のJSONパラメータ
  private static class AuthenticationResultParam {
    public byte[] credentialId;
    public byte[] clientDataJSON;
    public byte[] authenticatorData;
    public byte[] signature;
    public byte[] userHandle;
  }
}
