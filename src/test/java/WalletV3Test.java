import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;

import static org.junit.jupiter.api.Assertions.*;

class WalletV3Test {

    private WalletV3 wallet;

    @BeforeEach
    void setUp() {
        String apiUrl = "http://127.0.0.1:3420/v3/owner"; // Replace with your API URL
        String apiUser = "mwc";                // Replace with your API username
        String apiPassword = "MfinFl6TPlpsn5u2X4r6"; // Replace with your API password
        wallet = new WalletV3(apiUrl, apiUser, apiPassword);
    }

    @Test
    void testInitSecureApi() {
        try {
            System.out.println("Testing initSecureApi...");
            String sharedSecret = wallet.initSecureApi();
            assertNotNull(sharedSecret, "Shared secret should not be null");
            System.out.println("Shared Secret: " + sharedSecret);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception in initSecureApi: " + e.getMessage());
        }
    }

    @Test
    void testOpenWallet() {
        try {
            System.out.println("Testing openWallet...");
            wallet.initSecureApi();
            String token = wallet.openWallet("default", ""); // Replace with actual details
            assertNotNull(token, "Token should not be null");
            System.out.println("Token: " + token);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception in openWallet: " + e.getMessage());
        }
    }

    @Test
    void testRetrieveSummaryInfo() {
        try {
            System.out.println("Testing retrieveSummaryInfo...");
            wallet.initSecureApi();
            wallet.openWallet(null, ""); // Replace with actual details
            JsonObject summaryInfo = wallet.retrieveSummaryInfo(1, true);
            assertNotNull(summaryInfo, "Summary info should not be null");
            System.out.println("Summary Info: " + summaryInfo);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception in retrieveSummaryInfo: " + e.getMessage());
        }
    }

    @Test
    void testRetrieveTxs() {
        try {
            System.out.println("Testing retrieveTxs...");

            // Initialize Secure API
            wallet.initSecureApi();

            // Open Wallet
            wallet.openWallet(null, ""); // Replace with actual wallet name and password

            // Retrieve Transactions
            JsonArray transactions = wallet.retrieveTransactions(null, null, true); // Retrieve all transactions
            assertNotNull(transactions, "Transactions should not be null");
            assertTrue(transactions.size() > 0, "Transactions array should not be empty");
            System.out.println("Transactions: " + transactions.toString());
        } catch (Exception e) {
            e.printStackTrace();
            fail("Exception in retrieveTxs: " + e.getMessage());
        }
    }


}
