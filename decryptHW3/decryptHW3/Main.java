package decryptHW3;

/* PROBLEM:
 * 
The following ciphertext was generated using the code found at this link:
http://www.cs.ucf.edu/~dmarino/ucf/cis3362/progs/hill.java
HJLMYYBHFIKQSQEQAKWMSRYRKZPESYBGSCVDBHFBFLDRYKCPBHFQIAXTXDKK
EERJTLYPKOTSBDAMXGBHFACMSVXXNJQIVHHTECOJAADHMGZHTQWWQOWUPXME
CNJESHUUTNGUBDAOFVWQDUQHKOWJSAYFBOIVJBVOBGACFMKNMSERKYGYGRYE
RQAWQOBHFPFWOGAIIIVCQQOXYFICVDBHFGRMYKFIIIVCQOFVMFZYYYKBUMRT
WHXUOOBBEQRYWUOLVFJTQTONUWZDPDBHFXDUGKNWMRNGUBHFOKOCKHSHKSWT
VLZECBFPZLCKHSJCJJASB
The encryption key is a 3 x 3 matrix and the hint that will be given (to make decrypting easier) is
as follows:
All of the numbers in the 3 by 3 decryption key are taken from the following set: {0, 4, 5, 6, 8, 11,
16, 21, 22, 25}
 */

import java.util.*;
import java.util.concurrent.*;

public class Main {

    public static void decryptWithKey(String ciphertext, int[][] key) {
    	 int len = ciphertext.length();
    	    StringBuilder plaintext = new StringBuilder();

    	    // Transform the key by performing modulo 26 on each element
    	    // This is done to ensure that the values are within the range [0, 25]
    	    int[][] transformedKey = new int[3][3];
    	    for (int i = 0; i < 3; i++) {
    	        for (int j = 0; j < 3; j++) {
    	            transformedKey[i][j] = key[i][j] % 26;
    	        }
    	    }

    	    // Loop through the ciphertext in blocks of 3 characters
    	    for (int i = 0; i < len; i += 3) {
    	        int[] nums = {
    	            ciphertext.charAt(i) - 'A',
    	            ciphertext.charAt(i + 1) - 'A',
    	            ciphertext.charAt(i + 2) - 'A'
    	        };

    	        // Loop through each number in nums array
    	        for (int j = 0; j < 3; j++) {
    	            int plain = 0;
    	            for (int k = 0; k < 3; k++) {
    	                plain += transformedKey[j][k] * nums[k];
    	            }
    	            plain = plain % 26;
    	            plaintext.append((char) ('A' + plain));
    	        }
    	    }

    	    // Output the decrypted plaintext
    	    System.out.println("Decrypted plaintext:\n" + plaintext);
    }

    private static final Set<Integer> hintSet = Set.of(0, 4, 5, 6, 8, 11, 16, 21, 22, 25);

    public static boolean isHint(int num) {
        return hintSet.contains(num);
    }

    public static void bruteForceDecryption(String ciphertext) {
        ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

        List<Future<?>> futures = new ArrayList<>();

        int[][] key = new int[3][3];
        for (int i = 0; i <= 25; i++) {
            if (!isHint(i)) continue;
            key[0][0] = i;

            for (int j = 0; j <= 25; j++) {
                if (!isHint(j)) continue;
                key[0][1] = j;

                for (int k = 0; k <= 25; k++) {
                    if (!isHint(k)) continue;
                    key[0][2] = k;

                    for (int l = 0; l <= 25; l++) {
                        if (!isHint(l)) continue;
                        key[1][0] = l;

                        for (int m = 0; m <= 25; m++) {
                            if (!isHint(m)) continue;
                            key[1][1] = m;

                            for (int n = 0; n <= 25; n++) {
                                if (!isHint(n)) continue;
                                key[1][2] = n;

                                for (int o = 0; o <= 25; o++) {
                                    if (!isHint(o)) continue;
                                    key[2][0] = o;

                                    for (int p = 0; p <= 25; p++) {
                                        if (!isHint(p)) continue;
                                        key[2][1] = p;

                                        for (int q = 0; q <= 25; q++) {
                                            if (!isHint(q)) continue;
                                            key[2][2] = q;

                                            decryptWithKey(ciphertext, key);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        for (int i = 0; i <= 25; i++) {
            for (int q = 0; q <= 25; q++) {
                if (!isHint(q)) continue;
                key[2][2] = q;
                final int[][] finalKey = Arrays.stream(key).map(int[]::clone).toArray(int[][]::new);
                Future<?> future = executor.submit(() -> decryptWithKey(ciphertext, finalKey));
                futures.add(future);
            }
        }

        // Await termination of threads
        for (Future<?> future : futures) {
            try {
                future.get();
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
            }
        }

        executor.shutdown();
        try {
            if (!executor.awaitTermination(1, TimeUnit.HOURS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException ex) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public static void main(String[] args) {
        String ciphertext = "HJLMYYBHFIKQSQEQAKWMSRYRKZPESYBGSCVDBHFBFLDRYKCPBHFQIAXTXDKKEERJTLYPKOTSBDAMXGBHFACMSVXXNJQIVHHTECOJAADHMGZHTQWWQOWUPXMECNJESHUUTNGUBDAOFVWQDUQHKOWJSAYFBOIVJBVOBGACFMKNMSERKYGYGRYERQAWQOBHFPFWOGAIIIVCQQOXYFICVDBHFGRMYKFIIIVCQOFVMFZYYYKBUMRTWHXUOOBBEQRYWUOLVFJTQTONUWZDPDBHFXDUGKNWMRNGUBHFOKOCKHSHKSWTVLZECBFPZLCKHSJCJJASB";

        bruteForceDecryption(ciphertext.replaceAll(" ", ""));
    }
}

