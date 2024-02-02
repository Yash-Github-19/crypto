import com.google.gson.Gson;

import ai.crypto.security.client.algo.utils.CryptographicAlgorithm;
import ai.crypto.security.client.enums.AESModePadding;
import ai.crypto.security.client.enums.CryptographicAlgos;
import ai.crypto.security.client.enums.PrivateKeyFormat;
import ai.crypto.security.client.enums.PublicKeyFormat;
import ai.crypto.security.client.modal.DecryptedPayload;
import ai.crypto.security.client.modal.EncryptedPayload;
import ai.crypto.security.client.security.CryptoSecurityService;

public class Testing {

    public static void main(String[] args) {
        CryptographicAlgorithm crypto = CryptoSecurityService.init(CryptographicAlgos.AES, AESModePadding.GCM_NoPadding, PrivateKeyFormat.PKCS8, PublicKeyFormat.X509);

        String data = "hello world !!!";

        try {
            EncryptedPayload encyptedPayload = crypto.encrypt(data);
            System.err.println(new Gson().newBuilder().setPrettyPrinting().create().toJson(encyptedPayload));

            DecryptedPayload decyptedPayload = crypto.decrypt(new Gson().toJson(encyptedPayload));
            System.err.println(new Gson().newBuilder().setPrettyPrinting().create().toJson(decyptedPayload));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}