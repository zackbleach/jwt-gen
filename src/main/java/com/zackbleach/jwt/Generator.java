package com.zackbleach.jwt;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class Generator {

    public static void main(String[] args) throws JOSEException {
        if (args.length != 4) {
            System.out
                    .println("Incorrect usage, need arguments: subject, issuer, secret, expiresInSeconds");
            System.out.println("Found " + args.length + " arguments");
            System.exit(0);
        }

        String subject = args[0];
        checkNotNull(subject, "Error reading subject");
        System.out.println("Subject: " + subject);

        String issuer = args[1];
        checkNotNull(issuer, "Error reading issuer");
        System.out.println("Issuer: " + issuer);

        String secret = args[2];
        checkNotNull(secret, "Error reading secret");
        System.out.println("Secret: " + secret);

        int expiresInSeconds = 0;
        try {
            expiresInSeconds = Integer.parseInt(args[3]);
            System.out.println("Expires in: " + expiresInSeconds + " seconds");
        } catch (NumberFormatException e) {
            System.out.println("Error reding expiresInSeconds - not a number");
            System.exit(0);
        }

        System.out.println("JWT: "
                + getJwt(subject, issuer, secret, expiresInSeconds));
        System.exit(0);
    }

    private static String getJwt(String subject, String issuer, String secret,
            int expiresInSeconds) throws JOSEException {
        JWSSigner signer = new MACSigner(secret.getBytes());

        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setSubjectClaim(subject);
        claimsSet.setIssuedAtClaim(new Date().getTime());
        claimsSet.setIssuerClaim(issuer);
        claimsSet.setExpirationTimeClaim(new Date().getTime()
                + (expiresInSeconds * 1000));

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256),
                claimsSet);
        signedJWT.sign(signer);

        String jwt = signedJWT.serialize();
        return jwt;
    }
}
