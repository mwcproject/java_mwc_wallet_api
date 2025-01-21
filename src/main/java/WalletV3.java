import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.Base64;
import org.bitcoinj.core.ECKey;
import com.google.gson.*;

public class WalletV3 {

    private String apiUrl;
    private String apiUser;
    private String apiPassword;
    private ECKey ecKey;
    private String sharedSecret;
    private String token;

    public WalletV3(String apiUrl, String apiUser, String apiPassword) {
        this.apiUrl = apiUrl;
        this.apiUser = apiUser;
        this.apiPassword = apiPassword;
        this.ecKey = new ECKey(); // Generates a key pair with both public and private keys
        this.sharedSecret = "";
        this.token = "";
    }


    private String encrypt(String key, String msg, byte[] nonce) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(hexStringToByteArray(key), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] ciphertext = cipher.doFinal(msg.getBytes());
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    private String decrypt(String key, String data, byte[] nonce) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(hexStringToByteArray(key), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decodedData = Base64.getDecoder().decode(data);
        byte[] plaintext = cipher.doFinal(decodedData);
        return new String(plaintext);
    }

    private JsonObject post(String method, JsonObject params) throws Exception {
        JsonObject payload = new JsonObject();
        payload.addProperty("jsonrpc", "2.0");
        payload.addProperty("id", 1);
        payload.addProperty("method", method);
        payload.add("params", params);

        URL url = new URL(apiUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Authorization", "Basic " + Base64.getEncoder().encodeToString((apiUser + ":" + apiPassword).getBytes()));
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(payload.toString().getBytes());
        }

        if (conn.getResponseCode() >= 300 || conn.getResponseCode() < 200) {
            throw new Exception("HTTP Error: " + conn.getResponseCode());
        }

        InputStream is = conn.getInputStream();
        String response = new String(is.readAllBytes());
        is.close();

        JsonObject responseJson = JsonParser.parseString(response).getAsJsonObject();

        if (responseJson.has("error")) {
            throw new Exception("API Error: " + responseJson.get("error").toString());
        }

        return responseJson;
    }

    private JsonObject postEncrypted(String method, JsonObject params) throws Exception {
        JsonObject payload = new JsonObject();
        payload.addProperty("jsonrpc", "2.0");
        payload.addProperty("id", 1);
        payload.addProperty("method", method);
        payload.add("params", params);

        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        String encrypted = encrypt(sharedSecret, payload.toString(), nonce);

        JsonObject encryptedRequest = new JsonObject();
        encryptedRequest.addProperty("nonce", bytesToHex(nonce));
        encryptedRequest.addProperty("body_enc", encrypted);

        JsonObject resp = post("encrypted_request_v3", encryptedRequest);

        // Log the entire response for debugging
        System.out.println("Encrypted API Response: " + resp);

        JsonObject result = resp.getAsJsonObject("result");
        if (result == null || !result.has("Ok")) {
            throw new Exception("Unexpected response format or missing 'Ok' key in result: " + resp);
        }

        byte[] respNonce = hexStringToByteArray(result.getAsJsonObject("Ok").get("nonce").getAsString());
        String respEncrypted = result.getAsJsonObject("Ok").get("body_enc").getAsString();
        String decrypted = decrypt(sharedSecret, respEncrypted, respNonce);

        return JsonParser.parseString(decrypted).getAsJsonObject();
    }


    // Utility methods
    private byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public String initSecureApi() throws Exception {
        String pubkey = ecKey.getPublicKeyAsHex();
        System.out.println("Initializing Secure API with public key: " + pubkey);

        JsonObject params = new JsonObject();
        params.addProperty("ecdh_pubkey", pubkey);

        JsonObject resp = post("init_secure_api", params);
        System.out.println("Response from init_secure_api: " + resp);

        String remotePubkey = resp.getAsJsonObject("result").get("Ok").getAsString();
        System.out.println("Remote public key: " + remotePubkey);
        if (remotePubkey == null || remotePubkey.isEmpty()) {
            throw new Exception("Received an empty remote public key from the API.");
        }

        // Derive shared secret using secp256k1
        ECKey remoteKey = ECKey.fromPublicOnly(hexStringToByteArray(remotePubkey));
        byte[] sharedSecretBytes = remoteKey.getPubKeyPoint()
        .multiply(ecKey.getPrivKey()) // Use your private key to compute the shared secret
        .normalize()
        .getXCoord()
        .getEncoded();

        this.sharedSecret = bytesToHex(sharedSecretBytes);
        System.out.println("Shared Secret: " + this.sharedSecret);

        return this.sharedSecret;
    }



    public String openWallet(String name, String password) throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("name", name);
        params.addProperty("password", password);

        JsonObject resp = postEncrypted("open_wallet", params);

        // Log the response for debugging
        System.out.println("Open Wallet Response: " + resp);

        JsonObject result = resp.getAsJsonObject("result");
        if (result == null || !result.has("Ok")) {
            throw new Exception("Unexpected response format or missing 'Ok' key in result: " + resp);
        }

        this.token = result.get("Ok").getAsString();
        return this.token;
    }


    public JsonObject retrieveSummaryInfo(int minimumConfirmations, boolean refresh) throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("token", this.token);
        params.addProperty("minimum_confirmations", minimumConfirmations);
        params.addProperty("refresh_from_node", refresh);

        JsonObject resp = postEncrypted("retrieve_summary_info", params);

        // Log the response for debugging
        System.out.println("Retrieve Summary Info Response: " + resp);

        JsonObject result = resp.getAsJsonObject("result");
        if (result == null || !result.has("Ok")) {
            throw new Exception("Unexpected response format or missing 'Ok' key in result: " + resp);
        }

        JsonElement okElement = result.get("Ok");

        // Handle case where "Ok" is an array
        if (okElement.isJsonArray()) {
            JsonArray okArray = okElement.getAsJsonArray();
            if (okArray.size() > 1 && okArray.get(1).isJsonObject()) {
                return okArray.get(1).getAsJsonObject();
            } else {
                throw new Exception("Unexpected array format in 'Ok' key: " + okArray);
            }
        }

        // Handle case where "Ok" is an object (fallback)
        return okElement.getAsJsonObject();
    }

    public JsonArray retrieveTransactions(Integer txId, String slateTxId, boolean refresh) throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("token", this.token);
        params.addProperty("refresh_from_node", refresh);

        // Include tx_id and tx_slate_id, explicitly set to null if they are null
        params.add("tx_id", txId == null ? JsonNull.INSTANCE : new JsonPrimitive(txId));
        params.add("tx_slate_id", slateTxId == null ? JsonNull.INSTANCE : new JsonPrimitive(slateTxId));

        JsonObject resp = postEncrypted("retrieve_txs", params);

        // Log the response for debugging
        System.out.println("Retrieve Transactions Response: " + resp);

        JsonObject result = resp.getAsJsonObject("result");
        if (result == null || !result.has("Ok")) {
            throw new Exception("Unexpected response format or missing 'Ok' key in result: " + resp);
        }

        JsonElement okElement = result.get("Ok");

        // Expect 'Ok' to be an array where the second element is the transactions array
        if (okElement.isJsonArray()) {
            JsonArray okArray = okElement.getAsJsonArray();
            if (okArray.size() < 2 || !okArray.get(1).isJsonArray()) {
                throw new Exception("Unexpected format for 'Ok' key: " + okElement);
            }
            return okArray.get(1).getAsJsonArray(); // Return the transactions array
        } else {
            throw new Exception("Unexpected format for 'Ok' key: " + okElement);
        }
    }
}
