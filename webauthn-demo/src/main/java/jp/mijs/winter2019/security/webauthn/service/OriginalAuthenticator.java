package jp.mijs.winter2019.security.webauthn.service;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;

/**
 * 公開鍵クレデンシャルの実体
 */
public class OriginalAuthenticator implements Authenticator {
  private static final long serialVersionUID = -1382402688639693633L;

  private AttestedCredentialData attestedCredentialData;
  private AttestationStatement attestationStatement;
  private long counter;

  public OriginalAuthenticator(@JsonProperty("attestedCredentialData") AttestedCredentialData attestedCredentialData,
                               @JsonProperty("attestationStatement") AttestationStatement attestationStatement,
                               @JsonProperty("counter") long counter) {
    this.attestedCredentialData = attestedCredentialData;
    this.attestationStatement = attestationStatement;
    this.setCounter(counter);
  }

  @Override
  public AttestedCredentialData getAttestedCredentialData() {
      return this.attestedCredentialData;
  }
  
  @JsonTypeInfo(
          use = JsonTypeInfo.Id.NAME,
          include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
          property = "format"
  )
  @Override
  public AttestationStatement getAttestationStatement(){
      return this.attestationStatement;
  }

  @Override
  public long getCounter() {
      return this.counter;
  }

  @Override
  public void setCounter(long value) {
      this.counter = value;
  }

  @Override
  public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      OriginalAuthenticator that = (OriginalAuthenticator) o;
      return counter == that.counter &&
              Objects.equals(attestedCredentialData, that.attestedCredentialData) &&
              Objects.equals(attestationStatement, that.attestationStatement);
  }

  @Override
  public int hashCode() {
      return Objects.hash(attestedCredentialData, attestationStatement, counter);
  }
}
