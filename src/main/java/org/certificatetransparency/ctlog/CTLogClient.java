package org.certificatetransparency.ctlog;

import com.google.common.io.Files;
import org.bouncycastle.util.encoders.Hex;
import org.certificatetransparency.ctlog.comm.HttpLogClient;
import org.certificatetransparency.ctlog.proto.Ct;
import org.certificatetransparency.ctlog.serialization.CryptoDataLoader;
import org.certificatetransparency.ctlog.serialization.SerializationException;
import org.certificatetransparency.ctlog.serialization.Serializer;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.*;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * The main CT log client. Currently only knows how to upload certificate chains
 * to the ctlog.
 */
public class CTLogClient {
  private final HttpLogClient httpClient;
  private final LogSignatureVerifier signatureVerifier;

  private static final String DOWNLOAD_STRING = "download";
  private static final String UPLOAD_STRING = "upload";

  /**
   * Result of the certificate upload. Contains the SCT and verification result.
   */
  public static class UploadResult {
    private final Ct.SignedCertificateTimestamp sct;
    private final boolean verified;

    public UploadResult(Ct.SignedCertificateTimestamp sct, boolean verified) {
      this.sct = sct;
      this.verified = verified;
    }

    public boolean isVerified() {
      return verified;
    }

    public final Ct.SignedCertificateTimestamp getSct() {
      return sct;
    }
  }

  public CTLogClient(String baseLogUrl, LogInfo logInfo) {
    this.httpClient = new HttpLogClient(baseLogUrl);
    this.signatureVerifier = new LogSignatureVerifier(logInfo);
  }

  public UploadResult uploadCertificatesChain(List<Certificate> chain) {
    Ct.SignedCertificateTimestamp sct = httpClient.addCertificate(chain);
    return new UploadResult(sct, signatureVerifier.verifySignature(sct, chain.get(0)));
  }

  public static void usage() {
    System.out.println(
            String.format("Usage: %s %s <Log URL> <output path> [first=0] [last=treeSize]",
                    CTLogClient.class.getSimpleName(), DOWNLOAD_STRING));
    System.out.println(
            String.format("Usage: %s %s <Certificate chain> <Log URL> <Log public key> [output file]",
                    CTLogClient.class.getSimpleName(), UPLOAD_STRING));
    System.out.println(
            String.format("Example: %s download ct.googleapis.com/pilot ./pilot_ 32000000 32100000",
                    CTLogClient.class.getSimpleName()));

  }


  public static void main(String[] args) throws IOException {
    if (args.length < 3) {
      usage();
      return;
    }

    if (UPLOAD_STRING.equals(args[0])) {
      String pemFile = args[1];
      String logUrl = getBaseUrl(args[2]);
      String logPublicKeyFile = args[3];
      String outputSctFile = null;
      if (args.length >= 5) {
        outputSctFile = args[4];
      }

      CTLogClient client = new CTLogClient(logUrl, LogInfo.fromKeyFile(logPublicKeyFile));
      List<Certificate> certs = CryptoDataLoader.certificatesFromFile(new File(pemFile));
      System.out.println(String.format("Total number of certificates: %d", certs.size()));

      UploadResult result = client.uploadCertificatesChain(certs);
      if (result.isVerified()) {
        System.out.println("Upload successful ");
        if (outputSctFile != null) {
          byte[] serialized = Serializer.serializeSctToBinary(result.getSct());
          Files.write(serialized, new File(outputSctFile));
        }
      } else {
        System.out.println("Log signature verification FAILED.");
      }
    } else if (DOWNLOAD_STRING.equals(args[0])) {
      long firstEntry = 0;
      long entryCount = 0;

      String logUrl = getBaseUrl(args[1]);
      String outputPath = args[2];
      if (args.length > 3) firstEntry = Long.parseLong(args[3]);
      if (args.length > 4) entryCount = Long.parseLong(args[4]) - firstEntry + 1;

      long entriesPerRequest = 1024; // google pilot allows maximum 1024 records in a query

      long processedTotal = 0;
      long processedRSA = 0;
      long processedNotRSA = 0;

      HttpLogClient client = new HttpLogClient(logUrl);
      SignedTreeHead head = client.getLogSTH();
      long treeSize = head.treeSize;

      if (firstEntry >= treeSize) {
        System.err.println("First entry index exceeds the size of the log");
        return;
      }

      if (entryCount == 0) entryCount = treeSize - 1;

      if (treeSize < firstEntry + entryCount) {
        System.err.println("Required number of entries exceeds the size of the log, downloading until the end of the log");
        entryCount = treeSize - firstEntry;
      }

      System.out.println(treeSize);

      PrintStream ps = null;
      try {
        ps = new PrintStream(new BufferedOutputStream(new FileOutputStream(
                String.format("%s%d.txt", outputPath, head.timestamp))));
      } catch (FileNotFoundException e) {
        e.printStackTrace();
        return;
      }

      long requestCount = (entryCount + entriesPerRequest - 1) / entriesPerRequest;

      for (long request = 0; request < requestCount; request++) {
        long startEntry = firstEntry + request * entriesPerRequest;
        long endEntry = (request != requestCount - 1)
                ? (firstEntry + (request + 1) * entriesPerRequest - 1)
                : (firstEntry + entryCount - 1);

        System.out.println(String.format("%d - %d", startEntry, endEntry));

        List<ParsedLogEntry> logEntryList;

        try {
          logEntryList = client.getLogEntries(startEntry, endEntry);
        } catch (Exception e) {
          System.err.println("Error downloading log entries, repeating "
                  + String.format("%d - %d", startEntry, endEntry) + "\nCause: " +  e.getMessage());
          request--;
          continue;
        }

        ListIterator<ParsedLogEntry> iterator = logEntryList.listIterator();
        long idInRequest = -1;
        while (iterator.hasNext()) {
          idInRequest++;
          ParsedLogEntry entry;

          processedTotal++;

          try {
            entry = iterator.next();
          } catch (SerializationException e) {
            // ignore a problem with Deserializer and precertificates
            if (!"Extra data corrupted.".equals(e.getMessage())) {
              System.err.println(e.getMessage());
            }
            continue;
          }

          if (entry.getLogEntry().x509Entry != null) {
            byte[] leafCertBytes = entry.getLogEntry().x509Entry.leafCertificate;
            try {
              X509Certificate leafCert = (X509Certificate) CertificateFactory.getInstance("X509")
                      .generateCertificate(new ByteArrayInputStream(leafCertBytes));
              if (!"RSA".equals(leafCert.getPublicKey().getAlgorithm())) {
                processedNotRSA++;
                continue;
              }
              processedRSA++;
              long timestamp = 0;
              if (entry.getMerkleTreeLeaf() != null && entry.getMerkleTreeLeaf().timestampedEntry != null) {
                timestamp = entry.getMerkleTreeLeaf().timestampedEntry.timestamp;
              }
              ps.println(certificateToJsonString(leafCert, firstEntry + request * entriesPerRequest + idInRequest, timestamp));
            } catch (CertificateException | InvalidNameException e) {
              System.err.println(e.getMessage());
            }
          } else if (entry.getLogEntry().precertEntry != null) {
            System.err.println("Precertificate");
          } else {
            System.err.println("Unknown entry type");
          }
        }
      }

      ps.close();

      System.out.println(String.format("All records: %d; Valid certificates: %d; RSA: %d; Not RSA: %d",
              processedTotal, processedRSA + processedNotRSA, processedRSA, processedNotRSA));
    } else {
      usage();
    }
  }

  private static String getBaseUrl(String url) {
    return String.format("http://%s/ct/v1/", url);
  }

  private static String certificateToJsonString(X509Certificate cert, long certId, long timestamp) throws InvalidNameException {
    return certificateToJsonString(cert, false, certId, timestamp);
  }

  private static String certificateToJsonString(X509Certificate cert, boolean oldFormat, long certId, long timestamp) throws InvalidNameException {

    if (!"RSA".equals(cert.getPublicKey().getAlgorithm())) {
      return null;
    }

    String dnSubject = cert.getSubjectX500Principal().getName();
    String cnSubject = null;
    LdapName ldapDN = new LdapName(dnSubject);
    for(Rdn rdn: ldapDN.getRdns()) {
      if ("CN".equalsIgnoreCase(rdn.getType())) {
        cnSubject = rdn.getValue().toString();
      }
    }
    List<String> san = null;
    try {
      Collection<List<?>> sanCollection = cert.getSubjectAlternativeNames();
      if (sanCollection != null) {
        san = new ArrayList<>(4);
        for (List<?> list : sanCollection) {
          for (Object o : list) {
            if (o instanceof String) san.add((String) o);
          }
        }
      }
    } catch (CertificateParsingException e) {
      e.printStackTrace();
    }

    String dnIssuer = cert.getIssuerX500Principal().getName();
    String cnIssuer = null;
    LdapName ldapDNIssuer = new LdapName(dnIssuer);
    for(Rdn rdn: ldapDNIssuer.getRdns()) {
      if ("CN".equalsIgnoreCase(rdn.getType())) {
        cnIssuer = rdn.getValue().toString();
      }
    }

    RSAPublicKey key = (RSAPublicKey) cert.getPublicKey();

    JSONObject jsonResult = new JSONObject();

    if (oldFormat) {
      JSONObject jsonSubject = new JSONObject();
      jsonSubject.put("common_name", cnSubject);
      JSONObject jsonValidity = new JSONObject();
      jsonValidity.put("start", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(cert.getNotBefore()));
      jsonValidity.put("end", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(cert.getNotAfter()));
      JSONObject jsonIssuer = new JSONObject();
      jsonIssuer.put("common_name", cnIssuer);
      JSONObject jsonRSAPublicKey = new JSONObject();
      jsonRSAPublicKey.put("length", key.getModulus().bitLength());
      jsonRSAPublicKey.put("modulus", Hex.toHexString(key.getModulus().toByteArray()));
      jsonRSAPublicKey.put("exponent", key.getPublicExponent());

      jsonResult.put("subject", jsonSubject);
      jsonResult.put("validity", jsonValidity);
      jsonResult.put("issuer", jsonIssuer);
      jsonResult.put("rsa_public_key", jsonRSAPublicKey);
      jsonResult.put("timestamp", timestamp);
    } else {
      JSONArray jsonSource = new JSONArray();
      jsonSource.add(cnSubject);
      jsonSource.add(new SimpleDateFormat("yyyy-MM-dd").format(cert.getNotBefore()));


      jsonResult.put("source", jsonSource);
      jsonResult.put("n", String.format("0x%s", key.getModulus().toString(16)));
      jsonResult.put("e", String.format("0x%s", key.getPublicExponent().toString(16)));
      jsonResult.put("count", 1);
      jsonResult.put("id", certId);
      jsonResult.put("timestamp", timestamp);
      if (cnIssuer != null) jsonResult.put("issuercn", cnIssuer);
      jsonResult.put("cn", cnSubject);
      if (san != null) jsonResult.put("san", san);
    }

    return jsonResult.toString();
  }
}
