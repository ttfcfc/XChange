package org.knowm.xchange.binance.service;

import jakarta.ws.rs.QueryParam;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;


import org.knowm.xchange.binance.BinanceAuthenticated;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import si.mazi.rescu.Params;
import si.mazi.rescu.ParamsDigest;
import si.mazi.rescu.RestInvocation;

public class BinanceED25519Digest implements ParamsDigest {

  private static final Logger LOG = LoggerFactory.getLogger(BinanceED25519Digest.class);
  private final Charset charSet = StandardCharsets.UTF_8;
  private final PrivateKey privateKey;

  private BinanceED25519Digest(String secretKeyBase64) {
      PrivateKey tmpKey = null;
      try {
          // 解码 Base64 -> PKCS#8
          byte[] decodePrivateKey = Base64.getDecoder().decode(secretKeyBase64.getBytes(charSet));
          PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decodePrivateKey);
          KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
          tmpKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
      } catch (Exception e) {
          LOG.error("Failed to initialize Ed25519 private key", e);
      }
      this.privateKey = tmpKey;
  }

  public static BinanceED25519Digest createInstance(String secretKeyBase64) {
    return secretKeyBase64 == null ? null : new BinanceED25519Digest(secretKeyBase64);
  }

  /**
   * @return the query string except of the "signature" parameter
   */
  private static String getQuery(RestInvocation restInvocation) {
    final Params p = Params.of();
    restInvocation.getParamsMap().get(QueryParam.class).asHttpHeaders().entrySet().stream()
        .filter(e -> !BinanceAuthenticated.SIGNATURE.equals(e.getKey()))
        .forEach(e -> p.add(e.getKey(), e.getValue()));
    return p.asQueryString();
  }

  @Override
  public String digestParams(RestInvocation restInvocation) {
    final String input;

    switch (restInvocation.getHttpMethod()) {
      case "GET":
      case "DELETE":
        input = getQuery(restInvocation);
        break;
      case "POST":
        input = getQuery(restInvocation) + restInvocation.getRequestBody();
        break;
      case "PUT":
        input = getQuery(restInvocation) + restInvocation.getRequestBody();
        break;
      default:
        throw new RuntimeException("Not support http method: " + restInvocation.getHttpMethod());
    }
    try {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey);
        byte[] payloadBytes = input.getBytes(charSet);
        signature.update(payloadBytes);
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    } catch (Exception e) {
        LOG.error("", e);
    }
    return null;
  }
}
